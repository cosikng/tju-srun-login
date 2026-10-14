"""先以 IPv4 直连 mi.com 探测，再按网关返回的 AC 调用 CGI。"""

from dataclasses import dataclass
import logging
import math
import socket
import time
from urllib.parse import urlsplit
import uuid

import requests
from requests.adapters import HTTPAdapter

from .crypto import make_login_params
from .protocol import (PROBE_URL, AuthenticationError, ProbeResult, ProtocolError, SRunError,
                       TransportError, error_code, login_succeeded, online_identity,
                       parse_jsonp, parse_probe, valid_ipv4)

LOG = logging.getLogger("srun")
MAX_RESPONSE_BYTES = 65536


@dataclass(frozen=True)
class Config:
    portal: str = "http://202.113.9.18"
    connect_timeout: float = 5.0
    probe_read_timeout: float = 3.0
    normal_read_timeout: float = 15.0
    login_read_timeout: float = 35.0
    request_attempts: int = 3
    probe_attempts: int = 2
    login_attempts: int = 2
    backoff: float = 1.0

    def __post_init__(self):
        parsed = urlsplit(self.portal)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise ValueError("portal 必须是无路径、凭据和查询参数的 HTTP(S) 地址")
        try:
            parsed.port
        except ValueError:
            raise ValueError("portal 端口无效") from None
        for value in (self.connect_timeout, self.probe_read_timeout,
                      self.normal_read_timeout, self.login_read_timeout):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("超时必须为有限正数")
        if not all(1 <= v <= 10 for v in (self.probe_attempts, self.request_attempts, self.login_attempts)):
            raise ValueError("尝试次数必须在 1 到 10 之间")
        if not math.isfinite(self.backoff) or not 0 <= self.backoff <= 30:
            raise ValueError("退避基数必须在 0 到 30 秒之间")


class SRunClient:
    def __init__(self, config: Config | None = None, session=None, sleep=time.sleep):
        self.config = config or Config()
        self.session = session if session is not None else requests.Session()
        # 禁用 requests 环境/系统代理发现及 .netrc，并清除调用方代理设置。
        self.session.trust_env = False
        self.session.proxies.clear()
        self.session.auth = None
        self.session.headers.pop("Proxy-Authorization", None)
        self.session.headers.pop("Authorization", None)
        self.session.headers.pop("Cookie", None)
        self.session.mount("http://", HTTPAdapter(max_retries=0))
        self.session.mount("https://", HTTPAdapter(max_retries=0))
        self.session.headers.update({"User-Agent": "srun-minimal/2.0", "Accept": "*/*"})
        self.sleep = sleep
        self.request_count = 0
        self.timings = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        LOG.debug("本次共发送 %d 次 HTTP 请求", self.request_count)
        self.session.close()

    def _wait(self, attempt: int):
        delay = min(self.config.backoff * (2 ** attempt), 30)
        LOG.info("%.1f 秒后重试", delay)
        self.sleep(delay)

    def _fetch(self, url: str, label: str, params: dict | None, read_timeout: float, headers=None):
        start = time.monotonic()
        self.request_count += 1
        self.session.cookies.clear()
        self.session.proxies.clear()
        try:
            with self.session.get(url, params=params, headers=headers,
                                  timeout=(self.config.connect_timeout, read_timeout),
                                  proxies={"http": None, "https": None, "all": None},
                                  allow_redirects=False, stream=True) as response:
                LOG.debug("%s HTTP %s", label, response.status_code)
                chunks, size = [], 0
                for chunk in response.iter_content(chunk_size=4096):
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ProtocolError(label + " 响应过大，停止处理")
                    chunks.append(chunk)
                text = b"".join(chunks).decode("utf-8-sig", errors="replace")
                return response.status_code, dict(response.headers), text
        except requests.ConnectTimeout:
            raise TransportError(label + " 连接超时") from None
        except requests.ReadTimeout:
            raise TransportError(label + " 服务器响应超时") from None
        except requests.ConnectionError:
            raise TransportError(label + " 连接失败或响应中断") from None
        except requests.RequestException:
            raise TransportError(label + " HTTP 请求失败") from None
        finally:
            elapsed = time.monotonic() - start
            self.timings.append((label, elapsed))
            LOG.debug("%s 总耗时 %.3f 秒", label, elapsed)

    def probe(self) -> ProbeResult:
        LOG.info("探测 mi.com（HTTP / IPv4 直连）")
        host = urlsplit(PROBE_URL).hostname
        for attempt in range(self.config.probe_attempts):
            try:
                try:
                    addresses = [item for item in socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
                                 if item[0] == socket.AF_INET]
                    address = addresses[attempt % len(addresses)][4][0]
                    # 使用 IPv4 字面地址连接；Host 仍为站点域名。没有 IPv6 回退。
                    socket.inet_pton(socket.AF_INET, address)
                except (OSError, ValueError, IndexError, ZeroDivisionError):
                    raise TransportError("mi.com IPv4 DNS 解析失败") from None
                status, headers, text = self._fetch("http://" + address + "/", "mi.com 探测", None,
                                                    self.config.probe_read_timeout, {"Host": host})
                return parse_probe(status, headers, text, self.config.portal)
            except TransportError:
                if attempt + 1 == self.config.probe_attempts:
                    raise
                self._wait(attempt)
        raise AssertionError("unreachable")

    def _request(self, path: str, params: dict, login: bool = False) -> dict:
        if path not in ("/cgi-bin/rad_user_info", "/cgi-bin/get_challenge", "/cgi-bin/srun_portal"):
            raise ValueError("不支持的认证接口")
        callback = "srun_" + uuid.uuid4().hex
        query = dict(params, callback=callback, _=str(time.time_ns() // 1_000_000))
        status, _, text = self._fetch(self.config.portal.rstrip("/") + path, path, query,
                                      self.config.login_read_timeout if login else self.config.normal_read_timeout)
        if status != 200:
            raise TransportError(f"{path} 返回 HTTP {status}")
        return parse_jsonp(text, callback)

    def _read_request(self, path: str, params: dict) -> dict:
        for attempt in range(self.config.request_attempts):
            try:
                return self._request(path, params)
            except TransportError:
                if attempt + 1 == self.config.request_attempts:
                    raise
                self._wait(attempt)
        raise AssertionError("unreachable")

    def get_status(self) -> dict:
        # 仅供显式 status 命令；login 从不查询 Portal 在线状态。
        data = self._read_request("/cgi-bin/rad_user_info", {})
        online_identity(data)  # 未知错误不能当成离线状态。
        return data

    def get_challenge(self, username: str, ip: str = "") -> dict:
        LOG.info("获取 challenge")
        data = self._read_request("/cgi-bin/get_challenge", {"username": username, "ip": ip})
        if data.get("error") != "ok" or data.get("ecode", 0) not in (0, "0"):
            raise AuthenticationError("challenge 获取失败：" + error_code(data))
        token = data.get("challenge")
        if not isinstance(token, str) or not token or not token.isascii():
            raise ProtocolError("challenge 获取失败：缺少有效 token")
        # 前端 data.ip || response.client_ip。未指定 IP 时优先服务端视角。
        return {"token": token, "ip": valid_ipv4(ip or data.get("client_ip"))}

    @staticmethod
    def _ip_for_probe(probe: ProbeResult, explicit_ip: str) -> str:
        if explicit_ip and probe.ip and explicit_ip != probe.ip:
            raise ProtocolError("指定 IP 与网关探测返回的 IP 不一致，停止认证")
        return probe.ip or explicit_ip

    def login(self, username: str = "", password: str = "", *, verify: bool = False,
              ip: str = "", credentials=None) -> str:
        gate = self.probe()
        if gate.connected:
            LOG.info("探测站点已正常连通，跳过认证")
            return "already_connected"
        if ip:
            ip = valid_ipv4(ip)
        if credentials is not None:
            username, password = credentials()
        if not username or not password:
            raise ValueError("账号和密码不能为空")
        for attempt in range(self.config.login_attempts):
            current_ac = gate.ac_id
            LOG.info("网关返回 ac_id=%s；Portal：%s", current_ac, self.config.portal)
            challenge = self.get_challenge(username, self._ip_for_probe(gate, ip))
            current_ip = challenge["ip"]
            LOG.info("客户端 IP：%s", current_ip)
            params = make_login_params(username, password, current_ip, current_ac, challenge["token"])
            try:
                LOG.info("发送登录请求")
                result = self._request("/cgi-bin/srun_portal", params, login=True)
            except (TransportError, ProtocolError) as exc:
                LOG.info("%s；重新探测网络确认结果", exc)
                try:
                    gate = self.probe()
                except SRunError:
                    raise TransportError("登录结果不确定，网络探测失败；停止重发认证") from None
                if gate.connected:
                    LOG.info("探测站点已连通，停止认证重试")
                    return "recovered"
                if attempt + 1 == self.config.login_attempts:
                    raise TransportError("登录请求异常后仍收到认证跳转，已达到重试上限") from None
                self._wait(attempt)
                # 新轮次采用新探测返回的 AC，并重新取 token。
                continue
            if not login_succeeded(result):
                if (result.get("error") == "login_error"
                        and result.get("error_msg") == "INFO failed, BAS respond timeout."):
                    # 仅映射已验证的固定诊断，不直接打印未知服务端 error_msg。
                    raise AuthenticationError(
                        "认证失败：login_error；INFO failed, BAS respond timeout. "
                        f"（BAS 设备响应超时，网关返回 ac_id={current_ac}）")
                raise AuthenticationError("认证被拒绝：" + error_code(result))
            if verify:
                check = self.probe()
                if not check.connected:
                    raise AuthenticationError(
                        f"Portal 报告认证成功，但网络仍返回认证入口（ac_id={check.ac_id}）")
                LOG.info("认证成功，已确认探测站点连通")
            else:
                LOG.info("Portal 报告认证成功")
            return "login_ok"
        raise AssertionError("unreachable")

