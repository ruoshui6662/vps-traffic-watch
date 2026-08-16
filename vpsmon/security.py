# -*- coding: utf-8 -*-
"""vpsmon.security — 框架无关安全原语（仅 stdlib；Flask 蓝图与 stdlib Handler 共用）。

SPEC §13.2.2：从 api.py/app.py 提取，安全行为逐条对齐 SECURITY.md §4 与现状：

    client_ip(cfg, remote_addr, headers)  默认 remote_addr；配置 trusted_proxy 且来源
                                         匹配时采信 X-Forwarded-For 首段（防 XFF 伪造）
    ip_allowed(cfg, ip)                   allow_ips 空 = 放行；IP/CIDR（IPv4/IPv6）；
                                         IPv4-mapped IPv6 归并到 IPv4
    SlidingWindowRateLimiter(limit)       内存滑动窗口：window 秒内最多 limit 次/IP；
                                         0 = 关闭（不记录）；桶数 > 4096 清理空桶
    authenticate(cfg, headers, query)     token 空 = 放行；hmac.compare_digest 恒定时间
                                         比较 X-Token 头；allow_url_token=true 时追加
                                         ?token= 兼容；失败统一 401（由调用方应答）
    security_headers(path, is_secure)     安全响应头全量（CSP/XFO/nosniff/Referrer/
                                         Permissions/Cache-Control；is_secure 追加 HSTS）
    ensure_charset_utf8(ctype)            文本类 Content-Type 强制 charset=utf-8
                                          （T1 编码链路鲁棒化，双后端共用）
    valid_host(host_header, bind)         结构校验 + 端口校验 + IP 字面量放行 +
                                         主机名钉扎（防 Host 投毒/DNS rebinding）
    validate_iface(raw) / valid_month()   参数边界：iface 字符集 ^[A-Za-z0-9._-]{1,64}$；
                                         month 严格 YYYY-MM（01-12）
    clamp_int(raw, default, lo, hi)       limit/minutes 等数值参数边界
    rate_limit_value(cfg)                 rate_limit 配置归一（默认 60；0/负 = 关闭）

安全门顺序（由适配层执行）：白名单 403 → 限流 429 → 鉴权 401 → 参数校验 400
（与 Flask 版一致：before_request 白名单/限流 → 视图装饰器鉴权/iface → 视图内
month/minutes/limit）。

headers 参数为任何支持 .get("X-Token")/.get("X-Forwarded-For") 的映射
（Flask request.headers、http.server email.message.Message 均大小写不敏感）。

本模块仅依赖 stdlib。自检：python -m vpsmon.security --self-test
"""

import hmac
import ipaddress
import logging
import re
import socket
import threading
import time
from collections import deque
from urllib.parse import urlsplit

log = logging.getLogger("vpsmon.security")

# SECURITY §4.6 工作值（app.py 既有 _CSP 迁移，行为不变）
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
    "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

# SECURITY §4.8.4：iface 字符集白名单
IFACE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


# ---------------------------------------------------------------- 客户端 IP

def client_ip(cfg, remote_addr, headers) -> str:
    """请求来源 IP（SECURITY §4.2/§4.3）。

    默认取 remote_addr（防 XFF 伪造）；仅当配置 trusted_proxy 且请求确实来自
    该代理地址时，才采信 X-Forwarded-For 首段（反代场景真实客户端）。
    """
    addr = remote_addr or ""
    trusted = (cfg.get("trusted_proxy") or "").strip()
    if trusted and addr == trusted:
        xff = (headers.get("X-Forwarded-For") or "").strip()
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                addr = first
    return addr


# ---------------------------------------------------------------- IP 白名单

def ip_allowed(cfg, ip) -> bool:
    """IP 白名单判定（SECURITY §4.3）：allow_ips 空 = 放行；
    命中任一 IP/CIDR 条目放行；IPv4-mapped IPv6（::ffff:a.b.c.d）归并到 IPv4。"""
    entries = cfg.get("allow_ips") or []
    if not entries:
        return True
    try:
        cand = ipaddress.ip_address(ip.split("%", 1)[0].strip() or ip)
        if isinstance(cand, ipaddress.IPv6Address) and cand.ipv4_mapped is not None:
            cand = cand.ipv4_mapped
    except ValueError:
        return False
    for e in entries:
        try:
            if "/" in e:
                net = ipaddress.ip_network(e, strict=False)
                if cand.version == net.version and cand in net:
                    return True
            else:
                other = ipaddress.ip_address(e.split("%", 1)[0].strip() or e)
                if cand == other:
                    return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------- 限流

class SlidingWindowRateLimiter:
    """内存滑动窗口限流（SECURITY §4.2）：window 秒内最多 limit 次/IP。

    limit = 0（或负）→ 关闭（allow 恒 True，且不记录命中）；
    窗口裁剪后计数，超限拒绝；桶数 > max_buckets 时清理空桶（内存有界）。
    单进程内存态，重启清零（SECURITY §7.3 已文档化，单用户场景可接受）。
    """

    def __init__(self, limit=60, window=60.0, max_buckets=4096):
        self.limit = int(limit) if limit and int(limit) > 0 else 0
        self.window = float(window)
        self.max_buckets = int(max_buckets)
        self._lock = threading.Lock()
        self._hits = {}                    # ip -> deque[time.monotonic()]

    def allow(self, ip) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            dq = self._hits.get(ip)
            if dq is None:
                dq = deque()
                self._hits[ip] = dq
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) >= self.limit:
                return False
            dq.append(now)
            if len(self._hits) > self.max_buckets:
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True


def rate_limit_value(cfg) -> int:
    """rate_limit 配置归一（默认 60；0/负 = 关闭限流）。"""
    v = cfg.get("rate_limit", 60)
    try:
        v = int(v)
    except (TypeError, ValueError):
        return 60
    return v if v > 0 else 0


# ---------------------------------------------------------------- 鉴权

def authenticate(cfg, headers, query_token=None) -> bool:
    """token 鉴权（SECURITY H2/H3）：token 空 = 放行。

    headers: 支持 .get("X-Token") 的映射；query_token: ?token= 值（无则 None）。
    恒定时间比较；allow_url_token=false（默认）时 ?token= 一律无效。
    """
    token = (cfg.get("token") or "").strip()
    if not token:
        return True
    provided = headers.get("X-Token") or ""
    ok = hmac.compare_digest(provided, token)
    if not ok and cfg.get("allow_url_token", False) and query_token:
        ok = hmac.compare_digest(query_token, token)
    return ok


# ---------------------------------------------------------------- 响应头

def security_headers(path, is_secure=False) -> dict:
    """全量安全响应头（SECURITY M1/§4.6，与 app.py after_request 逐条一致）。

    /api/* → Cache-Control: no-store；/static/* → public, max-age=3600；
    / → public, max-age=300；其余 → no-store；is_secure（HTTPS）追加 HSTS。
    """
    h = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Content-Security-Policy": CSP,
    }
    if path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    elif path.startswith("/static/"):
        h["Cache-Control"] = "public, max-age=3600"
    elif path == "/":
        h["Cache-Control"] = "public, max-age=300"
    else:
        h["Cache-Control"] = "no-store"
    if is_secure:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return h


# ---------------------------------------------------------------- 编码链路（T1）

def ensure_charset_utf8(ctype) -> str:
    """文本类 Content-Type 强制 charset=utf-8（双后端共用，T1 编码链路鲁棒化）。

    乱码第一性原理：浏览器对文本资源按 响应头 charset 参数 → 页面内 meta 的
    顺序确定解码字符集；反代剥 charset / 旧缓存 / 国产浏览器系统默认（GBK）
    都可能让 UTF-8 内容按错误编码解码。此原语保证全文本资源
    （html/js/css/json/svg）的 Content-Type 一律携带 charset=utf-8：

    - None / 空 → 原样返回（不注入空头）；
    - 已含 charset（如 "text/html; charset=utf-8"）→ 原样返回（不重复追加）；
    - text/*（html/css/js/txt 等）与 application/json、application/javascript、
      application/x-javascript、image/svg+xml → 追加 "; charset=utf-8"；
    - 其余类型（image/png、application/octet-stream 等）→ 原样返回。

    注：mimetypes.guess_type 在部分平台/旧 Python（OpenWrt/NAS）对 .js 返回
    application/javascript，故显式纳入，防静态资源漏网。
    """
    if not ctype:
        return ctype
    if "charset" in ctype.lower():
        return ctype
    base = ctype.split(";", 1)[0].strip().lower()
    if (base.startswith("text/")
            or base in ("application/json", "application/javascript",
                        "application/x-javascript", "image/svg+xml")):
        return ctype + "; charset=utf-8"
    return ctype


# ---------------------------------------------------------------- Host 校验

def valid_host(host_header: str, bind: str) -> bool:
    """Host 头校验（SECURITY §4.8，防 Host 投毒/DNS rebinding）。

    - 缺失/结构非法（含 / \\ 空白 控制字符 @、解析失败）→ False；
    - 端口必须为空或 1-65535（非法端口 → urlsplit.port 抛 ValueError → False）；
    - IP 字面量（IPv4/IPv6）直接放行：IP 不参与 DNS 解析，无 rebinding 面；
    - 主机名必须 ∈ {bind, 127.0.0.1, localhost, ::1, 本机 hostname}，
      攻击者控制的任意域名无法通过校验。
    注：反代部署若透传域名，需将域名配置到 bind 或改为 IP 访问。
    """
    if not host_header or any(c in host_header for c in "/\\\x00\r\n @"):
        return False
    try:
        parsed = urlsplit("//" + host_header)
        hostname = parsed.hostname
        _port = parsed.port            # 越界/非数字端口 → ValueError
    except ValueError:
        return False
    if not hostname:
        return False
    hostname = hostname.strip().rstrip(".").lower()
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    allowed = {str(bind or "").strip().lower(), "127.0.0.1", "localhost", "::1"}
    try:
        allowed.add(socket.gethostname().lower())
    except Exception:
        pass
    return hostname in allowed


# ---------------------------------------------------------------- 参数边界

def validate_iface(raw) -> bool:
    """iface 参数字符集白名单（SECURITY §4.8.4）：^[A-Za-z0-9._-]{1,64}$。

    None / 空白（参数缺失或空值）→ 放行（与 Flask 版装饰器行为一致）；
    非空且不匹配 → False（调用方应答 400 invalid iface）。
    """
    if raw is None:
        return True
    s = str(raw).strip()
    if not s:
        return True
    return bool(IFACE_RE.match(s))


def valid_month(month) -> bool:
    """month 严格 YYYY-MM（4 位年 + 2 位零填充月，月份 01-12）。

    拒绝 '2026-1'/'26-01'/'202601' 等非规范写法（SECURITY 参数边界收紧）。
    """
    if not isinstance(month, str):
        return False
    if not _MONTH_RE.match(month):
        return False
    y, m = int(month[:4]), int(month[5:7])
    return 1 <= y <= 9999 and 1 <= m <= 12


def clamp_int(raw, default, lo, hi) -> int:
    """数值参数边界：缺失/非数字/越界 → default；否则原值（与 api._clamp_int 一致）。"""
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return default
    if v < lo or (hi is not None and v > hi):
        return default
    return v


# ---------------------------------------------------------------- 自检

def _self_test() -> None:
    ok = []

    def check(name, cond):
        ok.append(cond)
        print(("PASS  " if cond else "FAIL  ") + name)

    H = {"X-Token": "sekrit"}

    # ---- client_ip / trusted_proxy ----
    check("client_ip 默认 remote_addr",
          client_ip({}, "1.2.3.4", {}) == "1.2.3.4")
    check("client_ip 无代理配置忽略 XFF",
          client_ip({}, "1.2.3.4", {"X-Forwarded-For": "9.9.9.9"}) == "1.2.3.4")
    check("client_ip 信任代理采信 XFF 首段",
          client_ip({"trusted_proxy": "10.0.0.1"}, "10.0.0.1",
                    {"X-Forwarded-For": " 192.0.2.1 , 10.0.0.1"}) == "192.0.2.1")
    check("client_ip 非信任来源伪造 XFF 无效",
          client_ip({"trusted_proxy": "10.0.0.1"}, "10.0.0.9",
                    {"X-Forwarded-For": "192.0.2.1"}) == "10.0.0.9")

    # ---- ip_allowed ----
    check("allow_ips 空 = 放行", ip_allowed({}, "198.51.100.9"))
    wl = {"allow_ips": ["192.0.2.0/24", "2001:db8::/32", "1.2.3.4"]}
    check("CIDR v4 命中", ip_allowed(wl, "192.0.2.9"))
    check("CIDR v4 未命中", not ip_allowed(wl, "198.51.100.9"))
    check("CIDR v6 命中", ip_allowed(wl, "2001:db8::9"))
    check("CIDR v6 未命中", not ip_allowed(wl, "2001:db9::9"))
    check("精确 IP 命中", ip_allowed(wl, "1.2.3.4"))
    check("IPv4-mapped IPv6 归并命中 v4 条目",
          ip_allowed(wl, "::ffff:192.0.2.9"))
    check("非法 IP → False", not ip_allowed(wl, "not-an-ip"))

    # ---- SlidingWindowRateLimiter ----
    rl = SlidingWindowRateLimiter(3)
    check("限流前 3 次放行", [rl.allow("1.1.1.1") for _ in range(3)] == [True, True, True])
    check("第 4 次拒绝", not rl.allow("1.1.1.1"))
    check("不同 IP 独立计数", rl.allow("2.2.2.2"))
    rl0 = SlidingWindowRateLimiter(0)
    check("limit=0 关闭（恒放行且不记录）",
          all(rl0.allow("3.3.3.3") for _ in range(10))
          and len(rl0._hits) == 0)
    rlb = SlidingWindowRateLimiter(5, max_buckets=10)
    for i in range(15):
        rlb.allow("ip%d" % i)
    for i in range(20):
        rlb._hits["dead%d" % i] = deque()
    rlb.allow("new-ip")
    check("桶数超限清理空桶（内存有界）",
          len(rlb._hits) == 16
          and not any(k.startswith("dead") for k in rlb._hits))
    check("rate_limit_value 归一", rate_limit_value({}) == 60
          and rate_limit_value({"rate_limit": 0}) == 0
          and rate_limit_value({"rate_limit": "abc"}) == 60
          and rate_limit_value({"rate_limit": -3}) == 0)

    # ---- authenticate ----
    cfg_t = {"token": "sekrit"}
    check("token 空 = 放行", authenticate({}, H))
    check("X-Token 正确 → 放行", authenticate(cfg_t, H))
    check("X-Token 错误 → 拒绝", not authenticate(cfg_t, {"X-Token": "wrong"}))
    check("无头 → 拒绝", not authenticate(cfg_t, {}))
    check("?token= 默认拒绝（allow_url_token=false）",
          not authenticate(cfg_t, {}, "sekrit"))
    check("allow_url_token=true ?token= 兼容",
          authenticate({**cfg_t, "allow_url_token": True}, {}, "sekrit"))
    check("allow_url_token=true header 或 query 任一通过",
          authenticate({**cfg_t, "allow_url_token": True}, {"X-Token": "sekrit"}, "wrong")
          and authenticate({**cfg_t, "allow_url_token": True}, {"X-Token": "wrong"}, "sekrit"))

    # ---- security_headers ----
    h = security_headers("/api/status")
    check("API 头 nosniff/DENY/no-referrer/CSP",
          h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
          and h["Referrer-Policy"] == "no-referrer"
          and "script-src 'self'" in h["Content-Security-Policy"])
    check("API Cache-Control no-store", h["Cache-Control"] == "no-store")
    check("static Cache-Control public 3600",
          security_headers("/static/js/app.js")["Cache-Control"] == "public, max-age=3600")
    check("/ Cache-Control public 300",
          security_headers("/")["Cache-Control"] == "public, max-age=300")
    check("未知路径 no-store", security_headers("/x")["Cache-Control"] == "no-store")
    check("HTTPS 追加 HSTS / HTTP 不追加",
          "Strict-Transport-Security" in security_headers("/", True)
          and "Strict-Transport-Security" not in security_headers("/", False))

    # ---- ensure_charset_utf8（T1 编码链路鲁棒化） ----
    check("charset 强制 text/html",
          ensure_charset_utf8("text/html") == "text/html; charset=utf-8")
    check("charset 强制 text/css / text/javascript",
          ensure_charset_utf8("text/css") == "text/css; charset=utf-8"
          and ensure_charset_utf8("text/javascript") == "text/javascript; charset=utf-8")
    check("charset 强制 json / application-javascript / svg",
          ensure_charset_utf8("application/json") == "application/json; charset=utf-8"
          and ensure_charset_utf8("application/javascript")
          == "application/javascript; charset=utf-8"
          and ensure_charset_utf8("application/x-javascript")
          == "application/x-javascript; charset=utf-8"
          and ensure_charset_utf8("image/svg+xml") == "image/svg+xml; charset=utf-8")
    check("已含 charset 不重复追加",
          ensure_charset_utf8("text/html; charset=utf-8") == "text/html; charset=utf-8"
          and ensure_charset_utf8("text/html; charset=gbk") == "text/html; charset=gbk")
    check("非文本类型不加 charset",
          ensure_charset_utf8("image/png") == "image/png"
          and ensure_charset_utf8("application/octet-stream") == "application/octet-stream"
          and ensure_charset_utf8(None) is None and ensure_charset_utf8("") == "")

    # ---- valid_host ----
    check("Host 缺失 → False", not valid_host("", "0.0.0.0"))
    check("Host 未知域名 → False", not valid_host("evil.example.com", "0.0.0.0"))
    check("Host IP 字面量放行", valid_host("127.0.0.1:8080", "0.0.0.0"))
    check("Host IPv6 字面量放行", valid_host("[::1]:8080", "0.0.0.0"))
    check("Host localhost 放行", valid_host("localhost", "0.0.0.0"))
    check("Host 绑定的主机名放行", valid_host("mon.example", "mon.example"))
    check("Host userinfo（@）拒绝", not valid_host("evil.com@127.0.0.1:8080", "0.0.0.0"))
    check("Host 端口越界拒绝", not valid_host("127.0.0.1:99999", "0.0.0.0"))
    check("Host 端口非数字拒绝", not valid_host("127.0.0.1:abc", "0.0.0.0"))
    check("Host 含斜杠拒绝", not valid_host("evil.com/path", "0.0.0.0"))

    # ---- 参数边界 ----
    check("validate_iface None/空 → 放行",
          validate_iface(None) and validate_iface("") and validate_iface("  "))
    check("validate_iface 合法字符集 → 放行", validate_iface("eth0.v2_3-x"))
    check("validate_iface 非法字符 → 拒绝", not validate_iface("bad/iface"))
    check("validate_iface 超长 65 → 拒绝", not validate_iface("a" * 65))
    check("valid_month 严格 YYYY-MM", valid_month("2026-01") and not valid_month("2026-1")
          and not valid_month("2026-13") and not valid_month("202600")
          and not valid_month("") and not valid_month("abc") and not valid_month(None))
    check("clamp_int 边界",
          clamp_int("abc", 30, 5, 1440) == 30
          and clamp_int(None, 30, 5, 1440) == 30
          and clamp_int("9999", 30, 5, 1440) == 30
          and clamp_int("60", 30, 5, 1440) == 60
          and clamp_int("4", 30, 5, 1440) == 30)

    print("\nsecurity self-test: %d/%d passed" % (sum(ok), len(ok)))
    if not all(ok):
        raise SystemExit("security self-test FAILED")


if __name__ == "__main__":
    _self_test()
