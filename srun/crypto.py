"""按 SRun 前端 jquery.srun.portal.js / all.min.js 复现认证算法。"""

import base64
import hashlib
import hmac
import json
import struct

ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9


def _words(text: str, length: bool = False) -> list[int]:
    # JS 使用 UTF-16 charCodeAt，而不是 UTF-8 字节。保留其移位/OR 行为。
    raw = text.encode("utf-16-le", errors="surrogatepass")
    units = list(struct.unpack("<" + "H" * (len(raw) // 2), raw))
    words = []
    for i in range(0, len(units), 4):
        word = 0
        for j, unit in enumerate(units[i:i + 4]):
            word |= unit << (8 * j)
        words.append(word & MASK)
    if length:
        words.append(len(units))
    return words


def _mix(z: int, y: int, total: int, key: list[int], p: int, e: int) -> int:
    # 原 JS 将三个表达式相加，与通常 XXTEA 的 MX 括号不同。
    return (((z >> 5) ^ (y << 2))
            + (((y >> 3) ^ (z << 4)) ^ (total ^ y))
            + (key[(p & 3) ^ e] ^ z)) & MASK


def xencode(text: str, token: str) -> bytes:
    if not text:
        return b""
    v = _words(text, True)
    key = _words(token)
    key += [0] * max(0, 4 - len(key))
    z = v[-1]
    total = 0
    for _ in range(6 + 52 // len(v)):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(len(v)):
            y = v[(p + 1) % len(v)]
            z = v[p] = (v[p] + _mix(z, y, total, key, p, e)) & MASK
    return struct.pack("<" + "I" * len(v), *v)


def make_password(password: str, token: str) -> str:
    """md5(password, token)：token 为 HMAC key，password 为 message。"""
    return "{MD5}" + hmac.new(token.encode("utf-8"), password.encode("utf-8"), hashlib.md5).hexdigest()


def _js_json(value: dict) -> str:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    # 现代 JSON.stringify 将孤立 surrogate 转义；正常非 ASCII 保持原样。
    return "".join(f"\\u{ord(c):04x}" if 0xD800 <= ord(c) <= 0xDFFF else c for c in text)


def make_info(username: str, password: str, ip: str, ac_id: str, token: str) -> str:
    text = _js_json({"username": username, "password": password, "ip": ip,
                     "acid": str(ac_id), "enc_ver": "srun_bx1"})
    encoded = base64.b64encode(xencode(text, token)).decode("ascii")
    return "{SRBX1}" + encoded.translate(str.maketrans(STANDARD_ALPHABET, ALPHABET))


def make_checksum(username: str, digest: str, ac_id: str, ip: str, info: str, token: str) -> str:
    text = "".join(token + str(value) for value in (username, digest, ac_id, ip, 200, 1, info))
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def make_login_params(username: str, password: str, ip: str, ac_id: str, token: str) -> dict:
    password_field = make_password(password, token)
    info = make_info(username, password, ip, str(ac_id), token)
    return {"action": "login", "username": username, "password": password_field,
            "ac_id": str(ac_id), "ip": ip,
            "chksum": make_checksum(username, password_field[5:], str(ac_id), ip, info, token),
            "info": info, "n": "200", "type": "1",
            "os": "Mac OS", "name": "Macintosh", "double_stack": "0"}
