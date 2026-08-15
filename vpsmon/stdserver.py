# -*- coding: utf-8 -*-
"""vpsmon.stdserver — OpenWrt 纯标准库 HTTP 服务器（ThreadingHTTPServer，无 Flask）。

SPEC §13.2.3：与 Flask 版共用 api.py 纯处理器 handle_* 与 security.py 安全原语，
6 端点 JSON 逐字段一致。要点：

- 服务器：http.server.ThreadingHTTPServer（daemon_threads / allow_reuse_address）；
  HTTP/1.0 默认（每请求一连接，单用户足够）；
- 路由：精确路径匹配 6 个 /api/* 端点 + /（index.html）+ /static/*；
  未知路径 → 404 JSON；非 GET 方法 → 405 JSON（与 Flask 路由层语义一致：
  未知 /api/* 的 404/405 先于鉴权门，见 .devtest/integration.py 观察项）；
- 安全门顺序（仅命中 6 端点）：白名单 403 → 限流 429 → 鉴权 401 → iface 400
  → 处理器（month/minutes/limit 400 在处理器内）；
  非 GET 命中已知端点：先过 before_request 级门（白名单 403 → 限流 429）再 405。
  注：Flask 对非 GET 已知端点由路由层直接 405（before_request 不执行），本实现
  刻意更严——白名单/限流优先于 405，贴合 SECURITY §4.3"白名单优先"语义，实测
  两后端对未知路径 404 顺序一致（均先于门）；差异见 docs/SECURITY.md §4.12；
- 全请求先 Host 校验（与 app.py before_request 一致）；全响应注入安全头；
- 日志 query 串脱敏（复用 app._QueryRedactFilter 语义 → vpsmon.http logger）；
- TLS：ssl.SSLContext(PROTOCOL_TLS_SERVER) 包裹 socket；证书缺失 fail-closed；
- 静态文件：realpath 前缀防穿越 + mimetypes.guess_type + nosniff。

create_server(cfg, storage, collector) 返回可 serve_forever/shutdown 的 Server。
自检：python -m vpsmon.stdserver --self-test（无 Flask 可跑；契约对比需 Flask
时自动跳过并提示）。
"""

import http.server
import json
import logging
import mimetypes
import os
import re
import shutil
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit

from vpsmon import api as api_mod
from vpsmon import security as security_mod

log = logging.getLogger("vpsmon.http")

# 6 个 API 端点（精确匹配；其余 /api/* → 404，语义与 Flask 路由层一致）
_API_PATHS = frozenset({
    "/api/status",
    "/api/traffic/monthly",
    "/api/traffic/daily",
    "/api/traffic/live",
    "/api/history",
    "/api/interfaces",
})

_IFACE_ENDPOINTS = frozenset({
    "/api/status", "/api/traffic/monthly", "/api/traffic/daily",
    "/api/traffic/live", "/api/history",
})

_QUERY_REDACT = re.compile(r"\?[^ \"']*")


def _static_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def _tls_from_cfg(cfg):
    """cfg → TLS 上下文材料 (cert, key)；未配置 → None；配置但文件缺失 → ValueError。"""
    cert = (cfg.get("ssl_certfile") or "").strip()
    key = (cfg.get("ssl_keyfile") or "").strip()
    if not cert and not key:
        return None
    missing = [f for f in (cert, key) if f and not os.path.isfile(f)]
    if missing:
        raise ValueError("TLS 证书/密钥文件不存在: %s（拒绝以明文启动）"
                         % ", ".join(missing))
    return (cert, key)


class Server(http.server.ThreadingHTTPServer):
    """线程化 HTTP 服务器（含可选 TLS）。daemon_threads：线程不阻塞退出。"""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, cfg, storage, collector, tls=None):
        self.cfg = cfg
        self.storage = storage
        self.collector = collector
        self.rate_limiter = security_mod.SlidingWindowRateLimiter(
            security_mod.rate_limit_value(cfg))
        self.tls_active = tls is not None
        super().__init__(addr, Handler)
        if tls is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls[0], tls[1])
            self.socket = ctx.wrap_socket(self.socket, server_side=True)


def create_server(cfg, storage, collector, tls=None):
    """构建 stdlib 服务器。tls=None 时按 cfg 推导（缺失文件 → ValueError）。

    port：合法 1–65535 → 使用；显式 0 → 系统分配临时端口（测试用）；
    缺失/非法 → 8080（与 config.load_config 默认一致）。
    """
    if tls is None:
        tls = _tls_from_cfg(cfg)
    bind = str(cfg.get("bind") or "0.0.0.0")
    raw = cfg.get("port")
    if raw is None:
        port = 8080
    else:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            port = 8080
        if not (0 <= port <= 65535):
            port = 8080
    return Server((bind, port), cfg, storage, collector, tls)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "vpsmon/1.1"
    timeout = 30                      # 慢连接不长期占用线程（SPEC §13.2.3）

    # ------------------------------------------------------------ 分发

    def do_GET(self):
        self._dispatch()

    def _not_get(self):
        """非 GET：与 Flask 路由层语义一致——命中路径 → 405，未知路径 → 404。

        顺序复刻 Flask：before_request（白名单/限流）→ 路由（405/404）→ 视图
        （鉴权/参数校验在 405/404 之前不执行，见 .devtest/integration.py 观察项）。
        """
        try:
            parsed = urlsplit(self.path)
            path = parsed.path or "/"
            if not security_mod.valid_host(self.headers.get("Host", ""),
                                           self.server.cfg.get("bind", "")):
                self._send_json(400, {"ok": False, "error": "invalid host"})
                return
            if path in _API_PATHS:
                if self._method_gate(path, parse_qs(parsed.query, keep_blank_values=True)):
                    return
                self._send_json(405, {"ok": False, "error": "method not allowed"})
            elif path == "/" or path.startswith("/static/"):
                self._send_json(405, {"ok": False, "error": "method not allowed"})
            else:
                self._send_json(404, {"ok": False, "error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            log.exception("http handler error")
            try:
                self._send_json(500, {"ok": False, "error": "internal error"})
            except Exception:
                pass

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _not_get

    def _method_gate(self, path, qs):
        """非 GET 方法的安全门：仅 before_request 级（白名单 403 → 限流 429）。

        Flask 的 405/404 发生在视图之前，视图级鉴权/参数校验不执行，故此处
        不含 authenticate/validate_iface。
        """
        cfg = self.server.cfg
        ip = security_mod.client_ip(cfg, self.client_address[0], self.headers)
        if not security_mod.ip_allowed(cfg, ip):
            self._send_json(403, {"ok": False, "error": "forbidden"})
            return True
        if not self.server.rate_limiter.allow(ip):
            self._send_json(429, {"ok": False, "error": "rate_limited"})
            return True
        return False

    def _dispatch(self):
        try:
            parsed = urlsplit(self.path)
            path = parsed.path or "/"
            if not security_mod.valid_host(self.headers.get("Host", ""),
                                           self.server.cfg.get("bind", "")):
                self._send_json(400, {"ok": False, "error": "invalid host"})
                return
            if path in _API_PATHS:
                self._route_api(path, parse_qs(parsed.query, keep_blank_values=True))
            elif path == "/":
                self._serve_index()
            elif path.startswith("/static/"):
                self._serve_static(path)
            elif path.startswith("/api/"):
                self._send_json(404, {"ok": False, "error": "not found"})
            else:
                self._send_json(404, {"ok": False, "error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            log.exception("http handler error")
            try:
                self._send_json(500, {"ok": False, "error": "internal error"})
            except Exception:
                pass

    # ------------------------------------------------------------ API 门

    def _api_gate(self, path, qs):
        """安全门：白名单 403 → 限流 429 → 鉴权 401 → iface 400。
        命中任一拒绝并应答 → True；全部通过 → False。"""
        cfg = self.server.cfg
        ip = security_mod.client_ip(cfg, self.client_address[0], self.headers)
        if not security_mod.ip_allowed(cfg, ip):
            self._send_json(403, {"ok": False, "error": "forbidden"})
            return True
        if not self.server.rate_limiter.allow(ip):
            self._send_json(429, {"ok": False, "error": "rate_limited"})
            return True
        q_token = (qs.get("token") or [None])[0]
        if not security_mod.authenticate(cfg, self.headers, q_token):
            self._send_json(401, {"ok": False, "error": "unauthorized"})
            return True
        if path in _IFACE_ENDPOINTS:
            raw = (qs.get("iface") or [None])[0]
            if not security_mod.validate_iface(raw):
                self._send_json(400, {"ok": False, "error": "invalid iface"})
                return True
        return False

    def _route_api(self, path, qs):
        if self._api_gate(path, qs):
            return
        cfg = self.server.cfg
        storage = self.server.storage
        collector = self.server.collector

        def first(key, default=None):
            return (qs.get(key) or [default])[0]

        params = {"iface": first("iface"), "month": first("month"),
                  "minutes": first("minutes"), "limit": first("limit")}
        iface = api_mod.resolve_iface(params, collector)
        if path == "/api/status":
            code, body = api_mod.handle_status(cfg, storage, collector, iface)
        elif path == "/api/traffic/monthly":
            code, body = api_mod.handle_monthly(cfg, storage, collector, iface)
        elif path == "/api/traffic/daily":
            code, body = api_mod.handle_daily(cfg, storage, collector, iface,
                                              params["month"])
        elif path == "/api/traffic/live":
            code, body = api_mod.handle_live(cfg, storage, collector, iface,
                                             params["minutes"])
        elif path == "/api/history":
            code, body = api_mod.handle_history(cfg, storage, collector, iface,
                                                params["limit"])
        else:  # /api/interfaces
            code, body = api_mod.handle_interfaces(cfg, storage, collector)
        self._send_json(code, body)

    # ------------------------------------------------------------ 静态

    def _serve_index(self):
        idx = os.path.join(_static_dir(), "index.html")
        if os.path.isfile(idx):
            self._serve_file(idx, "text/html; charset=utf-8")
        else:
            # 与 Flask 版 index 兜底逐字一致（SPEC §13.2.3）
            self._send_json(404, {"ok": False, "error": "frontend not delivered yet"})

    def _serve_static(self, path):
        root = os.path.realpath(_static_dir())
        rel = path[len("/static/"):]
        full = os.path.realpath(os.path.join(root, rel))
        if not full.startswith(root + os.sep) or not os.path.isfile(full):
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        self._serve_file(full, ctype)

    def _serve_file(self, full, ctype):
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            self._send_json(404, {"ok": False, "error": "not found"})
            return
        self._send_bytes(200, data, ctype)

    # ------------------------------------------------------------ 响应

    def _send_json(self, code, body):
        # Flask jsonify 同款序列化：ensure_ascii=True + compact separators
        data = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self._send_bytes(code, data, "application/json; charset=utf-8")

    def _send_bytes(self, code, data, ctype):
        path = urlsplit(self.path).path or "/"
        headers = security_mod.security_headers(path, self.server.tls_active)
        headers["Content-Type"] = ctype
        headers["Content-Length"] = str(len(data))
        try:
            self.send_response(code)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ------------------------------------------------------------ 日志

    def log_message(self, fmt, *args):
        """access log 查询串脱敏（SECURITY M5，与 app._QueryRedactFilter 同语义）。"""
        try:
            msg = fmt % args
        except Exception:
            msg = fmt
        if "?" in msg:
            msg = _QUERY_REDACT.sub("?redacted", msg)
        log.info("%s - - [%s] %s", self.address_string(),
                 self.log_date_time_string(), msg)


# ---------------------------------------------------------------- 自检

def _self_test() -> None:
    """stdlib 服务器端到端断言 + 双后端契约对比（需 Flask 时自动启用）。"""
    import http.client
    from datetime import date

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmpdir = os.path.join(root, "vpsmon_http_test_%d_%d"
                          % (int(time.time()), os.getpid()))
    os.makedirs(tmpdir, exist_ok=True)
    ok = []

    def check(name, cond):
        ok.append(cond)
        print(("PASS  " if cond else "FAIL  ") + name)

    class FakeCollector:
        selected = "eth0"
        hostname = "test-host"
        uptime = 12345

    server = None
    flask_available = False
    try:
        st = api_mod.storage_mod.Storage(os.path.join(tmpdir, "t.db"))
        st.init_db()
        now = int(time.time())
        base = now - 200
        for i in range(4):
            st.insert_sample({"ts": base + i * 50, "iface": "eth0",
                              "rx_bytes": 1000 + i * 100, "tx_bytes": 2000 + i * 100,
                              "cpu": 10.0 + i, "mem_used": 1024, "mem_total": 2048,
                              "disk_used": 4096, "disk_total": 8192})
        st.insert_sample({"ts": now, "iface": "eth1", "rx_bytes": 99, "tx_bytes": 99,
                          "cpu": 5.0, "mem_used": 1, "mem_total": 2,
                          "disk_used": 3, "disk_total": 4})
        fake = FakeCollector()

        # ---- TLS fail-closed：证书缺失 → create_server 拒绝 ----
        try:
            create_server({"bind": "127.0.0.1", "port": 0,
                           "ssl_certfile": os.path.join(tmpdir, "no.pem"),
                           "ssl_keyfile": os.path.join(tmpdir, "no-key.pem")},
                          st, fake)
            check("TLS 证书缺失 → 拒绝启动（fail-closed）", False)
        except ValueError:
            check("TLS 证书缺失 → 拒绝启动（fail-closed）", True)
        # 未配置 TLS → 正常创建
        cfg = {"bind": "127.0.0.1", "port": 0, "token": "sekrit",
               "rate_limit": 60, "allow_ips": [], "allow_url_token": False}
        server = create_server(cfg, st, fake)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        # ---- 双后端契约：Flask 版（同一库同一 fake）逐字段对比 ----
        try:
            import vpsmon.app as app_mod
            import vpsmon.api as api_pkg
            api_pkg.configure(cfg, st, fake)
            app = app_mod.create_app(cfg, st, fake)
            fc = app.test_client()
            flask_available = True
        except ImportError:
            fc = None

        def _parse(raw):
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return raw.decode("utf-8", "replace")

        def http_get(path, headers=None, method="GET"):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            h = dict(headers or {})
            conn.request(method, path, headers=h)
            r = conn.getresponse()
            data = r.read()
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            conn.close()
            return r.status, _parse(data), hdrs

        def flask_get(path, headers=None, method="GET"):
            r = fc.open(path, method=method, headers=headers or {})
            return r.status_code, _parse(r.get_data()), \
                {k.lower(): v for k, v in r.headers.items()}

        def compare(path, headers=None):
            s1, b1, _ = http_get(path, headers=headers)
            s2, b2, _ = flask_get(path, headers=headers)
            same = (s1 == s2 and b1 == b2)
            check("契约 %s 双后端一致 (status=%s)" % (path, s1), same)
            if not same:
                print("    stdlib:", s1, b1)
                print("    flask :", s2, b2)
            return same

        H = {"X-Token": "sekrit"}
        if flask_available:
            compare("/api/status", H)
            compare("/api/traffic/monthly", H)
            compare("/api/traffic/daily?month=%04d-%02d" % (date.today().year,
                                                            date.today().month), H)
            compare("/api/traffic/live?minutes=9999", H)
            compare("/api/history?limit=2", H)
            compare("/api/interfaces", H)
            # 错误路径契约
            compare("/api/traffic/daily?month=2026-1", H)
            compare("/api/history?iface=bad/iface&limit=1", H)
            compare("/api/nonexistent", H)
            compare("/api/nonexistent")
            compare("/", None)
            compare("/static/js/app.js", None)
            compare("/static/../vpsmon/app.py", None)
        else:
            print("  [注] Flask 未安装：跳过双后端契约对比（仅 stdlib 断言）")

        # ---- 鉴权 ----
        st2, b2, _ = http_get("/api/status")
        check("无 token → 401 统一体", st2 == 401 and b2 == {"ok": False, "error": "unauthorized"})
        st2, b2, _ = http_get("/api/status?token=sekrit")
        check("?token= 默认拒绝 401", st2 == 401)
        st2, b2, _ = http_get("/api/status?token=wrong")
        check("?token= 错误 → 401", st2 == 401)
        st2, b2, _ = http_get("/api/status", headers={"X-Token": "wrong"})
        check("错误 X-Token → 401", st2 == 401)
        st2, b2, _ = http_get("/api/status", headers=H)
        check("X-Token 头通过 200", st2 == 200 and b2["ok"])

        # ---- 安全响应头 ----
        st2, b2, hdrs = http_get("/api/status", headers=H)
        check("API 安全头 nosniff/DENY/no-referrer/CSP",
              hdrs.get("x-content-type-options") == "nosniff"
              and hdrs.get("x-frame-options") == "DENY"
              and hdrs.get("referrer-policy") == "no-referrer"
              and "script-src 'self'" in (hdrs.get("content-security-policy") or ""))
        check("API Cache-Control no-store", hdrs.get("cache-control") == "no-store")
        check("JSON Content-Type", (hdrs.get("content-type") or "").startswith("application/json"))
        st2, b2, hdrs = http_get("/")
        check("静态页安全头 + 放宽缓存",
              hdrs.get("x-frame-options") == "DENY"
              and (hdrs.get("cache-control") or "").startswith("public"))
        st2, b2, hdrs = http_get("/static/js/app.js")
        check("static 200 + nosniff", st2 == 200
              and hdrs.get("x-content-type-options") == "nosniff")

        # ---- 路由：404/405 ----
        st2, b2, _ = http_get("/api/nonexistent", headers=H)
        check("未知 API 路径 → 404 JSON（先于鉴权）",
              st2 == 404 and b2 == {"ok": False, "error": "not found"})
        st2, b2, _ = http_get("/nonexistent")
        check("未知非 API 路径 → 404 JSON", st2 == 404 and b2["ok"] is False)
        st2, b2, _ = http_get("/api/status", headers=H, method="POST")
        check("POST 已知端点 → 405 JSON（先于鉴权）",
              st2 == 405 and b2 == {"ok": False, "error": "method not allowed"})
        st2, b2, _ = http_get("/api/status", method="POST")
        check("POST 已知端点无 token → 405 JSON（视图级鉴权不执行，同 Flask）",
              st2 == 405 and b2 == {"ok": False, "error": "method not allowed"})
        st2, b2, _ = http_get("/", method="POST")
        check("POST / → 405 JSON", st2 == 405)
        st2, b2, _ = http_get("/api/nonexistent", method="POST")
        check("POST 未知路径 → 404 JSON", st2 == 404)

        # ---- 参数边界 ----
        st2, b2, _ = http_get("/api/history?iface=bad/iface&limit=1", headers=H)
        check("iface 非法字符 → 400 invalid iface",
              st2 == 400 and b2 == {"ok": False, "error": "invalid iface"})
        st2, b2, _ = http_get("/api/history?iface=%s&limit=1" % ("a" * 65), headers=H)
        check("iface 超长 65 → 400", st2 == 400)
        st2, b2, _ = http_get("/api/history?iface=eth0.v2_3-x&limit=1", headers=H)
        check("iface 合法字符集 → 200", st2 == 200)
        st2, b2, _ = http_get("/api/traffic/daily?month=2026-1", headers=H)
        check("month=2026-1 → 400（错误体逐字一致）",
              st2 == 400 and b2 == {"ok": False, "error": "invalid month, expect YYYY-MM"})
        st2, b2, _ = http_get("/api/traffic/daily?month=2026-01", headers=H)
        check("month=2026-01 → 200", st2 == 200)
        st2, b2, _ = http_get("/api/traffic/live?minutes=abc", headers=H)
        check("live minutes 非数字回退 30", st2 == 200 and b2["ok"])
        st2, b2, _ = http_get("/api/history?limit=0", headers=H)
        check("history limit=0 回退 100", st2 == 200 and b2["ok"])

        # ---- Host 校验 ----
        st2, b2, _ = http_get("/api/status", headers={"X-Token": "sekrit",
                                                      "Host": "evil.example.com"})
        check("Host 未知域名 → 400 invalid host",
              st2 == 400 and b2 == {"ok": False, "error": "invalid host"})
        st2, b2, _ = http_get("/api/status", headers={"X-Token": "sekrit",
                                                      "Host": "127.0.0.1:%d" % port})
        check("Host IP 字面量放行 → 200", st2 == 200)

        # ---- 限流（独立服务器） ----
        rl_cfg = dict(cfg, token="", rate_limit=3)
        srv_rl = create_server(rl_cfg, st, fake)
        prl = srv_rl.server_address[1]
        trl = threading.Thread(target=srv_rl.serve_forever, daemon=True)
        trl.start()
        codes = []
        for _ in range(5):
            conn = http.client.HTTPConnection("127.0.0.1", prl, timeout=5)
            conn.request("GET", "/api/status")
            r = conn.getresponse()
            r.read()
            codes.append(r.status)
            conn.close()
        check("限流前 3 次 200，第 4/5 次 429", codes[:3] == [200, 200, 200]
              and codes[3] == 429 and codes[4] == 429)
        conn = http.client.HTTPConnection("127.0.0.1", prl, timeout=5)
        conn.request("GET", "/api/status")
        r = conn.getresponse()
        body = json.loads(r.read().decode("utf-8"))
        conn.close()
        check("429 JSON {ok:false,error:rate_limited}",
              r.status == 429 and body == {"ok": False, "error": "rate_limited"})
        srv_rl.shutdown()
        srv_rl.server_close()

        # ---- 白名单（独立服务器） ----
        wl_cfg = dict(cfg, token="", allow_ips=["127.0.0.1"])
        srv_wl = create_server(wl_cfg, st, fake)
        pwl = srv_wl.server_address[1]
        twl = threading.Thread(target=srv_wl.serve_forever, daemon=True)
        twl.start()
        conn = http.client.HTTPConnection("127.0.0.1", pwl, timeout=5)
        conn.request("GET", "/api/status")
        r = conn.getresponse()
        r.read()
        in_ok = r.status
        conn.close()
        wl_bad = dict(cfg, token="", allow_ips=["192.0.2.0/24"])
        srv_wb = create_server(wl_bad, st, fake)
        pwb = srv_wb.server_address[1]
        twb = threading.Thread(target=srv_wb.serve_forever, daemon=True)
        twb.start()
        conn = http.client.HTTPConnection("127.0.0.1", pwb, timeout=5)
        conn.request("GET", "/api/status")
        r = conn.getresponse()
        body = json.loads(r.read().decode("utf-8"))
        conn.close()
        check("白名单内 → 200", in_ok == 200)
        check("白名单外 → 403 forbidden",
              r.status == 403 and body == {"ok": False, "error": "forbidden"})
        srv_wl.shutdown()
        srv_wl.server_close()
        srv_wb.shutdown()
        srv_wb.server_close()

        # ---- 白名单 + 非 GET 已知端点：stdserver 先过门再 405（刻意比 Flask 严）----
        # Flask 由路由层直接 405（before_request 不执行）；本实现白名单/限流优先，
        # 贴合 SECURITY §4.3 白名单优先语义（T8 实测确认，见 docs/SECURITY.md §4.12）。
        wl_post = dict(cfg, token="", allow_ips=["192.0.2.0/24"])
        srv_wp = create_server(wl_post, st, fake)
        pwp = srv_wp.server_address[1]
        twp = threading.Thread(target=srv_wp.serve_forever, daemon=True)
        twp.start()
        conn = http.client.HTTPConnection("127.0.0.1", pwp, timeout=5)
        conn.request("POST", "/api/status")
        r = conn.getresponse()
        r.read()
        wp_code = r.status
        conn.close()
        check("白名单外 POST 已知端点 → 403（先于 405，白名单优先语义）",
              wp_code == 403)
        srv_wp.shutdown()
        srv_wp.server_close()

        # ---- allow_url_token=true 兼容 ----
        ut_cfg = dict(cfg, allow_url_token=True)
        if flask_available:
            api_pkg.configure(ut_cfg, st, fake)
        srv_ut = create_server(ut_cfg, st, fake)
        put_ = srv_ut.server_address[1]
        tut = threading.Thread(target=srv_ut.serve_forever, daemon=True)
        tut.start()
        conn = http.client.HTTPConnection("127.0.0.1", put_, timeout=5)
        conn.request("GET", "/api/status?token=sekrit")
        r = conn.getresponse()
        r.read()
        url_ok = r.status
        conn.close()
        check("allow_url_token=true ?token= → 200", url_ok == 200)
        srv_ut.shutdown()
        srv_ut.server_close()

        # ---- 日志 query 脱敏（捕获 vpsmon.http logger） ----
        recs = []

        class _Capture(logging.Handler):
            def emit(self, record):
                recs.append(record.getMessage())

        cap = _Capture()
        http_logger = logging.getLogger("vpsmon.http")
        http_logger.setLevel(logging.INFO)      # 默认有效级别 WARNING 会滤掉 info
        http_logger.addHandler(cap)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/status?token=sekrit&a=1", headers=H)
        r = conn.getresponse()
        r.read()
        conn.close()
        time.sleep(0.1)
        joined = "\n".join(recs)
        check("access log 查询串脱敏（token 不出日志）",
              "?token=sekrit" not in joined and "?redacted" in joined)
        http_logger.removeHandler(cap)

        # ---- 静态文件穿越防护 ----
        st2, b2, _ = http_get("/static/../vpsmon/app.py")
        check("静态穿越 /static/../vpsmon/app.py → 404", st2 == 404)
        st2, b2, _ = http_get("/static/../../requirements.txt")
        check("静态穿越 /static/../../requirements.txt → 404", st2 == 404)
        st2, b2, _ = http_get("/static/js/app.js")
        check("静态正常文件 200", st2 == 200)

        # ---- / 路由 ----
        st2, b2, hdrs = http_get("/")
        check("GET / → 200 index.html",
              st2 == 200 and "text/html" in (hdrs.get("content-type") or ""))
        st2, b2, _ = http_get("/")
        check("/ 免鉴权", st2 == 200)

        server.shutdown()
        server.server_close()
        st.close()
    finally:
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\nstdserver self-test: %d/%d passed" % (sum(ok), len(ok)))
    if not all(ok):
        raise SystemExit("stdserver self-test FAILED")


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        _self_test()
    else:
        print("用法: python -m vpsmon.stdserver --self-test")
