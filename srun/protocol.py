"""JSON / JSONP 与 SRun 响应验证，不执行响应中的 JavaScript。"""

import ipaddress
import json
import re
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

PROBE_URL = "http://mi.com/"


class SRunError(Exception):
    """可安全显示的错误；不包含原始 URL、响应或认证参数。"""


class ProtocolError(SRunError):
    pass


class TransportError(SRunError):
    pass


class AuthenticationError(SRunError):
    pass


@dataclass(frozen=True)
class ProbeResult:
    ac_id: str | None = None
    ip: str = ""

    @property
    def connected(self) -> bool:
        return self.ac_id is None


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.scripts = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script" and not dict(attrs).get("src"):
            self.current = []

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self.current is not None:
            self.scripts.append("".join(self.current))
            self.current = None


def parse_probe(status: int, headers: dict, text: str, portal: str) -> ProbeResult:
    """只识别已捕获的两种 mi.com 响应，不执行 JS，不跟随跳转。"""
    parser = _Scripts()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):
        raise ProtocolError("探测响应 HTML 格式异常，停止认证") from None
    targets = []
    for script in parser.scripts:
        match = re.fullmatch(
            r"\s*(?:(?:window|document)\.)?location(?:\.href)?\s*=\s*(['\"])(.*?)\1\s*;?\s*",
            script, re.DOTALL)
        if match:
            targets.append(unescape(match[2]).replace(r"\/", "/"))
    if targets:
        if status != 200 or len(set(targets)) != 1:
            raise ProtocolError("探测响应中的 JS 跳转不明确，停止认证")
        try:
            target, expected = urlsplit(targets[0]), urlsplit(portal)
            if (target.scheme != expected.scheme or target.hostname != expected.hostname
                    or (target.port or (443 if target.scheme == "https" else 80))
                    != (expected.port or (443 if expected.scheme == "https" else 80))
                    or target.username or target.password or target.fragment):
                raise ValueError
        except ValueError:
            raise ProtocolError("JS 跳转不指向已配置的认证服务器，停止认证") from None
        query = parse_qs(target.query, keep_blank_values=True)
        match = re.fullmatch(r"/index_([0-9]{1,10})\.html", target.path)
        if match:
            ac_id = match[1]
            if "ac_id" in query and query["ac_id"] != [ac_id]:
                raise ProtocolError("认证入口的 AC 编号相互冲突")
        elif target.path == "/srun_portal_pc" and len(query.get("ac_id", [])) == 1:
            ac_id = query["ac_id"][0]
        else:
            raise ProtocolError("JS 认证入口中缺少有效 AC 编号")
        if not re.fullmatch(r"[0-9]{1,10}", ac_id) or int(ac_id) == 0:
            raise ProtocolError("JS 认证入口中的 AC 编号无效")
        ips = []
        for name in ("tjusip", "sip", "ip"):
            if name in query:
                if len(query[name]) != 1:
                    raise ProtocolError("认证入口包含多个客户端 IP")
                ips.append(valid_ipv4(query[name][0]))
        if len(set(ips)) > 1:
            raise ProtocolError("认证入口的客户端 IP 相互冲突")
        return ProbeResult(ac_id=ac_id, ip=ips[0] if ips else "")

    # 认证后的真实抓包：mi.com 返回正常的 HTTPS 站点重定向。
    # HTTP 200、错误页、其他跳转均不自动判为在线，避免把拦截页当成放行。
    try:
        location = urlsplit(next((v for k, v in headers.items() if k.lower() == "location"), ""))
        normal = (status in (301, 302, 303, 307, 308)
                  and location.scheme == "https" and location.hostname == "www.mi.com"
                  and location.port in (None, 443) and location.path == "/"
                  and not location.username and not location.password
                  and not location.query and not location.fragment)
    except ValueError:
        normal = False
    if normal:
        return ProbeResult()
    raise ProtocolError("探测结果不明确：未识别到正常站点响应或有效 JS 认证入口，停止认证")


def parse_jsonp(text: str, callback: str | None = None) -> dict:
    text = text.strip().lstrip("\ufeff").strip()
    if text.startswith("{"):
        raw = text
    else:
        match = re.fullmatch(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\((.*)\)\s*;?", text, re.DOTALL)
        if not match or (callback is not None and match[1] != callback):
            raise ProtocolError("JSONP 解析失败：格式或 callback 不匹配")
        raw = match[2]
    try:
        result = json.loads(raw)
    except (ValueError, RecursionError):
        raise ProtocolError("JSONP 解析失败：非法 JSON") from None
    if not isinstance(result, dict):
        raise ProtocolError("JSONP 解析失败：预期 JSON 对象")
    return result


def valid_ip(value) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
            raise ValueError
        return str(ip)
    except (ValueError, TypeError):
        raise ProtocolError("服务器未提供有效客户端 IP；可通过 --ip 指定") from None


def valid_ipv4(value) -> str:
    ip = valid_ip(value)
    if ipaddress.ip_address(ip).version != 4:
        raise ProtocolError("本次认证需要有效 IPv4 客户端地址")
    return ip


def error_code(data: dict) -> str:
    # 只显示短错误标识，防止服务端回显秘密或终端控制字符。
    value = data.get("error")
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_:-]{1,80}", value) else "unknown_error"


def login_succeeded(data: dict) -> bool:
    return (data.get("error") == "ok"
            and (data.get("res") == "ok" or data.get("suc_msg") == "login_ok")
            and data.get("ecode", 0) in (0, "0"))


def online_identity(data: dict) -> tuple[str, str] | None:
    if data.get("error") == "not_online_error" and data.get("res", "not_online_error") == "not_online_error":
        return None
    if data.get("error") != "ok" or data.get("ecode", 0) not in (0, "0"):
        raise ProtocolError("状态查询失败：" + error_code(data))
    username = data.get("user_name") or data.get("username")
    if not isinstance(username, str) or not username:
        raise ProtocolError("在线状态缺少账号，无法确认认证结果")
    ip = valid_ip(data.get("online_ip") or data.get("client_ip"))
    return username, ip
