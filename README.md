# SRun IPv4 校园网认证客户端

使用 Python 直接调用 SRun Portal CGI，启动时通过固定 HTTP 站点探测网络，并从认证网关的 JavaScript 跳转取得当次 AC。无需浏览器，不下载 Portal 页面、CSS、JS、图片或成功页面。

## 安装

需要 Python 3.10 或更新版本。运行依赖只有 requests。

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Windows 可通过 `.venv\Scripts\activate` 激活虚拟环境。

## 登录

在仓库目录运行：

```bash
python3 main.py login -u '<你的账号>' --verbose
```

已连通时直接退出，不询问账号或密码；确认需要认证后才提示输入密码，输入不回显。

也可由运行环境注入 `SRUN_USERNAME` 和 `SRUN_PASSWORD`。不要把真实密码写进源码、命令参数或提交到仓库。终端无法隐藏密码输入时停止，并提示改用环境变量。

```bash
python3 main.py login --verify --verbose
```

`--verify` 在 Portal 报告登录成功后再探测一次，确认探测站点能够访问。

## 流程与探测规则

固定探测地址为 `http://mi.com/`，认证主机默认 `http://202.113.9.18`，可通过 `--portal` 覆盖。

| 探测结果 | 行为 |
| --- | --- |
| HTTP 301/302/303/307/308，Location 为 `https://www.mi.com/` | 已连通，跳过认证 |
| HTTP 200，简单 JS 赋值跳转到已配置 Portal 的 `index_N.html` 或带 `ac_id` 的 Portal 入口 | 提取 AC，获取 challenge，再登录 |
| 超时、错误页、未知 HTTP 200、其他跳转或仅有链接 | 报错并停止，不猜测 AC |

只静态解析已知 JS 跳转，不执行 JavaScript，不跟随 HTTP 跳转。认证入口的主机、协议和端口必须与配置相符。

- 已连通：正常路径 **1 次 HTTP 请求**。
- 需要认证：正常路径 **3 次**，探测 → challenge → login。
- 启用 `--verify`：成功后追加探测，共 **4 次**。

登录不查询 `rad_user_info`；超时恢复和 `--verify` 也通过外部站点探测。AC 没有默认值或手动指定选项，`SRUN_AC_ID` 不读取；`--minimal` 仅作为旧命令兼容参数。

网关跳转的 `tjusip`、`sip` 或 `ip` 提供客户端 IPv4；没有地址时采用 challenge 的 `client_ip`。`--ip` 可显式指定 IPv4，但与网关地址冲突时停止。

## IPv4 与代理

探测只解析 A 地址，以 IPv4 字面地址连接并保留 `Host: mi.com`，不回退 IPv6，避免 IPv6 免认证造成误判。默认认证主机也是 IPv4 地址。

共享 Session 关闭环境/系统 HTTP 代理发现，清除 Session 代理并逐请求明确禁用 HTTP、HTTPS、ALL 代理；不读取 `.netrc`，不携带浏览器 Cookie。不修改系统代理设置。TUN/VPN、透明代理及系统路由不受这些设置控制。

仅验证探测站点的 IPv4 HTTP 响应，不能代表所有目标、HTTPS 或 IPv6 的状态。如果探测站点改变响应格式，程序会报告结果不明确，需要更新识别规则。

## 超时与恢复

```bash
python3 main.py login -u '<你的账号>' \
  --connect-timeout 5 --probe-read-timeout 3 --probe-attempts 2 \
  --read-timeout 15 --login-read-timeout 35 \
  --request-attempts 3 --login-attempts 2 --backoff 1 --verbose
```

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--connect-timeout` | 5 秒 | HTTP 连接超时 |
| `--probe-read-timeout` | 3 秒 | 探测读取超时 |
| `--probe-attempts` | 2 | 每次探测最大尝试次数，包含首次 |
| `--read-timeout` | 15 秒 | challenge/显式 status 读取超时 |
| `--login-read-timeout` | 35 秒 | login 读取超时 |
| `--request-attempts` | 3 | challenge/显式 status 最大尝试次数 |
| `--login-attempts` | 2 | 登录轮数上限，每轮使用新 challenge |
| `--backoff` | 1 秒 | 指数退避基数，单次最多 30 秒 |

登录超时、响应中断或 JSONP 无法解析时重新探测：已连通则停止重发；仍有明确认证跳转才退避，并用新的 AC/challenge 重试；探测失败或不明确则停止。明确业务拒绝立即报错。

取得 challenge 后立即生成参数并登录，HTTP 库不自动重放旧登录请求。DNS 使用系统解析器，各请求超时不是整个流程的硬性总时限。短连接超时只能控制等待，不能保证修复网络设备的 TCP 兼容性问题。

`--verbose` 显示请求状态、总耗时及次数，不记录密码、Cookie、token、HMAC、info、checksum 或完整登录 URL。

## 手动状态查询

```bash
python3 main.py status
```

此命令只查询 Portal 在线状态，不代表外网连通性。当前提供 login/status，不提供自动退出。

退出码：成功 0；配置、探测、认证或协议/网络错误 1；命令行解析错误 2；取消输入 130。

## 测试

```bash
python3 -m unittest discover -v
```

测试不访问网络，不需要 Node.js、原始 JS 或抓包。传输通过内存 Adapter 替换，保留真实 requests 的参数准备、代理合并和重定向处理；DNS 也使用测试数据。

算法测试使用 70 组人工输入及预先对照原始前端 JS 得到的参考输出，覆盖长度边界、短 key、中文、emoji、引号、反斜杠和换行。所有测试账号、密码、token 均为人工示例；客户端地址采用 RFC 5737 文档专用地址，没有真实设备 IP。

## 代码结构

```text
main.py                     命令行入口
srun/cli.py                 参数、交互输入和日志
srun/client.py              IPv4 探测、HTTP、重试与认证流程
srun/protocol.py            JS 跳转、JSONP 与业务结果解析
srun/crypto.py              本校 XEncode、自定义 Base64、HMAC-MD5、SHA-1
tests/                      无网络的回归测试
tests/fixtures/             公开人工参考向量
requirements.txt            运行依赖
```

认证 info 按顺序包含 username、password、ip、字符串 acid、enc_ver=srun_bx1，再经 XEncode 和自定义 Base64 编码。密码字段为 challenge 作 key 的 HMAC-MD5；checksum 为 challenge 与各认证参数按前端顺序拼接后的 SHA-1。改变 AC 时重新生成 info 与 checksum。

仓库只包含客户端、必要测试和说明；不包含个人账号密码、抓包、浏览器资料或本地分析记录。
