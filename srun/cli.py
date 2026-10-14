import argparse
import getpass
import logging
import os
import sys
import warnings

from .client import Config, SRunClient
from .protocol import SRunError, online_identity


def read_credentials(username):
    username = username or input("Username: ").strip()
    password = os.environ.get("SRUN_PASSWORD") or ""
    if not password:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass("Password: ")
        except getpass.GetPassWarning:
            raise SRunError("终端无法隐藏密码输入，请通过 SRUN_PASSWORD 环境变量提供密码") from None
    return username, password


def main(argv=None):
    parser = argparse.ArgumentParser(description="IPv4 直连 mi.com 探测，从 JS 认证跳转自动取得 AC 后登录")
    parser.add_argument("command", choices=("login", "status"))
    parser.add_argument("-u", "--username", default=os.environ.get("SRUN_USERNAME"))
    parser.add_argument("--portal", default="http://202.113.9.18")
    parser.add_argument("--ip", default="", help="显式指定客户端 IP，默认使用服务器返回值")
    parser.add_argument("--minimal", action="store_true", help="兼容旧命令；新流程始终先探测，再最小认证")
    parser.add_argument("--verify", action="store_true", help="登录响应成功后额外探测 mi.com，不查询在线状态")
    parser.add_argument("--connect-timeout", type=float, default=5)
    parser.add_argument("--probe-read-timeout", type=float, default=3)
    parser.add_argument("--read-timeout", type=float, default=15)
    parser.add_argument("--login-read-timeout", type=float, default=35)
    parser.add_argument("--request-attempts", type=int, default=3)
    parser.add_argument("--probe-attempts", type=int, default=2)
    parser.add_argument("--login-attempts", type=int, default=2)
    parser.add_argument("--backoff", type=float, default=1)
    parser.add_argument("--verbose", action="store_true", help="显示每个请求总耗时，不输出认证秘密")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    # 只开启本客户端的 DEBUG，urllib3 的 DEBUG 会暴露完整 query string。
    logging.getLogger("srun").setLevel(logging.DEBUG if args.verbose else logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    try:
        config = Config(portal=args.portal, connect_timeout=args.connect_timeout,
                        probe_read_timeout=args.probe_read_timeout, probe_attempts=args.probe_attempts,
                        normal_read_timeout=args.read_timeout, login_read_timeout=args.login_read_timeout,
                        request_attempts=args.request_attempts, login_attempts=args.login_attempts,
                        backoff=args.backoff)
        with SRunClient(config) as client:
            if args.command == "login":
                client.login(verify=args.verify, ip=args.ip,
                             credentials=lambda: read_credentials(args.username))
            elif args.command == "status":
                identity = online_identity(client.get_status())
                if identity is None:
                    logging.info("Portal 显示当前未在线")
                else:
                    logging.info("Portal 在线账号：%s；IP：%s", identity[0], identity[1])
        return 0
    except (SRunError, ValueError) as exc:
        logging.error("%s", exc)
        return 1
    except (EOFError, KeyboardInterrupt):
        logging.error("输入取消")
        return 130


if __name__ == "__main__":
    sys.exit(main())
