# -*- coding: utf-8 -*-
"""vpsmon.app — 入口：配置 → 存储 → 采集线程 → Web 服务（Flask / 纯标准库双后端）。

SPEC §3 / §7 + §13.2.4：启动时探测 Flask——
  可用 → Flask 路径（create_app + app.run，行为零变化）；
  不可用 → stdlib 服务器（stdserver.create_server，OpenWrt 纯标准库路径）。
两后端共用同一套 config/Storage/Collector/api 纯处理器/security 安全原语，
6 端点 API 契约逐字段一致（SPEC §13.2.2/§13.6 验收 2）。

用法：python -m vpsmon.app [--config <path>] [--db <path>] [--port <n>]
                          [--interval <n>] [--selftest]
      也支持直接执行脚本：python vpsmon/app.py ...（等价，见下方导入兼容说明）

- --config 优先级最高，其次 VPSMON_CONFIG 环境变量，再探测 /var/lib/vpsmon/config.json
  与 ./config.json，最后内置默认（config.load_config，SPEC §4.2）；
- 数据库默认位于配置文件同目录 vpsmon.db，--db 显式覆盖（SPEC §3）；
- 初始化 Storage → 启动 Collector（daemon 线程，唯一写库者）→ 装配 API
  （Flask 蓝图或 stdlib 路由）→ 静态页 / 与 /static/* → 按 cfg["bind"] 监听；
- TLS：cfg 中 ssl_certfile+ssl_keyfile 均配置且文件存在时启用（Flask
  ssl_context / stdlib ssl 包裹 socket）；证书缺失则拒绝启动（不静默降级明文）；
- 安全加固（SECURITY.md §4.6/§4.7/§4.8，原语集中在 security.py）：
  * 全量安全响应头（CSP/X-Frame-Options/nosniff/Referrer-Policy/
    Permissions-Policy/Cache-Control，API 强制 no-store；HTTPS 追加 HSTS）；
  * Host 头校验（结构合法 + 主机名钉扎，防 DNS rebinding）；
  * werkzeug access log 查询串脱敏（query string → ?redacted，防 ?token= 入日志）；
  * debug 强制 False（配置 true 也会被 config.load_config 回退）；
- --selftest：Flask 可用 → 现有端到端安全断言；不可用 → 依次跑
  procmetrics/security/stdserver 三个 stdlib 自检（含 stdlib 安全断言）后退出。
"""

import argparse
import logging
import os
import re
import sys
import time

# ---- 直接脚本执行兼容（NAS/systemd 以 `python vpsmon/app.py` 方式运行）----
# 以 -m 运行（python -m vpsmon.app）时 __package__ == "vpsmon"，包内相对导入可用；
# 直接执行脚本时 __package__ 为空，`from . import ...` 必然 ImportError。
# 这里在直接模式下先把项目根目录（app.py 的父目录）插入 sys.path 最前，
# 并统一改用绝对导入（from vpsmon import ...）——两种运行方式语义一致；
# 包内其他模块（api.py 等）的相对导入不受影响：绝对导入以 vpsmon.* 名义加载时
# 其 __package__ 为 "vpsmon"，包内相对导入照常解析。
if __package__ in (None, ""):
    _PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _PROJECT_ROOT not in sys.path:
        sys.path.insert(0, _PROJECT_ROOT)

from vpsmon import api as api_mod
from vpsmon import collector as collector_mod
from vpsmon import config as config_mod
from vpsmon import security as security_mod
from vpsmon import stdserver as stdserver_mod
from vpsmon import storage as storage_mod

log = logging.getLogger("vpsmon.app")


def _has_flask() -> bool:
    """SPEC §13.2.4：启动时探测一次 Flask（stdlib 路径 import 期不触碰 flask）。"""
    try:
        import flask  # noqa: F401
        return True
    except Exception:
        return False


def _parse_args(argv=None):
    p = argparse.ArgumentParser(description="VPS 流量统计监控系统")
    p.add_argument("--config", metavar="PATH", help="配置文件路径（最高优先级，覆盖 VPSMON_CONFIG）")
    p.add_argument("--db", metavar="PATH", help="显式指定数据库路径（覆盖 §3 推导规则）")
    p.add_argument("--port", type=int, help="监听端口（覆盖配置文件，范围 1-65535）")
    p.add_argument("--interval", type=int, help="采集间隔秒（覆盖配置文件，范围 5-86400）")
    p.add_argument("--selftest", action="store_true", help="运行端到端自检后退出（不监听）")
    return p.parse_args(argv)


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


class _QueryRedactFilter(logging.Filter):
    """werkzeug access log 查询串脱敏（SECURITY §4.7）："?..." → "?redacted"。

    werkzeug 默认 access log 记录完整 self.path（含 query string），
    H3 关闭 ?token= 后此面收敛，脱敏为纵深防御（防其余敏感参数入日志）。
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True                       # 参数不匹配等异常：原样放行
        if "?" in msg:
            record.msg = re.sub(r"\?[^ \"']*", "?redacted", msg)
            record.args = ()
        return True


def _install_redact_filter() -> None:
    """给 werkzeug logger 挂脱敏过滤器（幂等）。"""
    logger = logging.getLogger("werkzeug")
    for f in logger.filters:
        if isinstance(f, _QueryRedactFilter):
            return
    logger.addFilter(_QueryRedactFilter())


def create_app(cfg, storage, collector):
    """组装 Flask app（api 蓝图 + 错误处理 + 安全响应头 + Host 校验 + 静态页）。

    供测试与 main 复用。安全钩子对所有请求生效（原语来自 security.py，
    SPEC §13.2.2，与 stdlib 后端行为一致）：
    - before_request：Host 头校验（非法 → 400 JSON）；
    - after_request：安全响应头全量注入（API 强制 no-store，静态页放宽缓存）。
    """
    from flask import Flask, jsonify, request, send_from_directory

    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    if os.path.isdir(static_dir):
        app = Flask(__name__, static_folder=static_dir, static_url_path="/static")
    else:
        app = Flask(__name__)
        log.warning("static/ 目录尚不存在（前端未交付），静态资源暂不可用")

    app.register_blueprint(api_mod.create_blueprint(), url_prefix="/api")

    @app.route("/")
    def index():
        if os.path.isdir(static_dir) and os.path.isfile(os.path.join(static_dir, "index.html")):
            return send_from_directory(static_dir, "index.html")
        return jsonify({"ok": False, "error": "frontend not delivered yet"}), 404

    @app.before_request
    def _guard_host():
        if not security_mod.valid_host(request.headers.get("Host", ""), cfg.get("bind", "")):
            return jsonify({"ok": False, "error": "invalid host"}), 400
        return None

    @app.after_request
    def _security_headers(resp):
        for k, v in security_mod.security_headers(request.path, request.is_secure).items():
            resp.headers[k] = v
        return resp

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"ok": False, "error": "not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify({"ok": False, "error": "method not allowed"}), 405

    @app.errorhandler(500)
    def internal_error(_e):
        log.exception("internal error")
        return jsonify({"ok": False, "error": "internal error"}), 500

    return app


def main(argv=None) -> int:
    args = _parse_args(argv)
    _setup_logging()
    _install_redact_filter()
    if args.selftest:
        if _has_flask():
            return _self_test()
        return _stdlib_self_test()

    cfg = config_mod.load_config(args.config)
    config_mod.apply_overrides(cfg, port=args.port, interval=args.interval, db_path=args.db)

    # TLS：仅当 cert+key 均配置且文件存在时启用；证书缺失 → 拒绝以明文启动
    ssl_ctx = None
    scheme = "http"
    if cfg.get("ssl_certfile") and cfg.get("ssl_keyfile"):
        missing = [f for f in (cfg["ssl_certfile"], cfg["ssl_keyfile"])
                   if not os.path.isfile(f)]
        if missing:
            log.error("TLS 证书/密钥文件不存在: %s（拒绝以明文启动，请检查配置）",
                      ", ".join(missing))
            return 1
        ssl_ctx = (cfg["ssl_certfile"], cfg["ssl_keyfile"])
        scheme = "https"

    log.info("config: port=%s interval=%s iface=%r db=%s bind=%s rate_limit=%s tls=%s",
             cfg["port"], cfg["interval"], cfg["iface"], cfg["db_path"],
             cfg["bind"], cfg["rate_limit"], "on" if ssl_ctx else "off")

    storage = storage_mod.Storage(cfg["db_path"])
    storage.init_db()
    collector = collector_mod.Collector(storage, cfg)
    collector.start()
    api_mod.configure(cfg, storage, collector)

    # SPEC §13.2.4：后端自动选择（仅启动时判定一次）
    if _has_flask():
        app = create_app(cfg, storage, collector)
        try:
            log.info("vpsmon (flask) listening on %s://%s:%d (iface=%s)",
                     scheme, cfg["bind"], cfg["port"], collector.selected or "(auto)")
            app.run(host=cfg["bind"], port=cfg["port"], ssl_context=ssl_ctx,
                    debug=False, use_reloader=False)
        except KeyboardInterrupt:
            log.info("收到中断，正在退出…")
        finally:
            collector.stop()
            storage.close()
            log.info("vpsmon 已退出")
        return 0

    # stdlib 后端（OpenWrt 路径，纯标准库）
    try:
        server = stdserver_mod.create_server(cfg, storage, collector, tls=ssl_ctx)
    except ValueError as e:
        log.error("%s", e)
        collector.stop()
        storage.close()
        return 1
    try:
        log.info("vpsmon (stdlib) listening on %s://%s:%d (iface=%s)",
                 scheme, cfg["bind"], cfg["port"], collector.selected or "(auto)")
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("收到中断，正在退出…")
    finally:
        server.server_close()
        collector.stop()
        storage.close()
        log.info("vpsmon 已退出")
    return 0


def _stdlib_self_test() -> int:
    """SPEC §13.6 验收 1：无 flask/psutil 环境下的 stdlib 自检链。"""
    import vpsmon.procmetrics as procmetrics_mod
    import vpsmon.security as security_mod
    import vpsmon.stdserver as stdserver_mod
    for fn in (procmetrics_mod._self_test, security_mod._self_test,
               stdserver_mod._self_test):
        fn()
    print("\nstdlib self-test: all passed")
    return 0


# ---------------------------------------------------------------- 端到端自检

def _self_test() -> int:
    """端到端自检：真实装配（临时库）+ 安全断言（头/鉴权/限流/白名单/参数/Host/日志脱敏）。"""
    import shutil

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmpdir = os.path.join(root, "vpsmon_app_test_%d_%d"
                          % (int(time.time()), os.getpid()))
    os.makedirs(tmpdir, exist_ok=True)
    ok = []

    def check(name, cond):
        ok.append(cond)
        print(("PASS  " if cond else "FAIL  ") + name)

    class FakeCollector:
        selected = "eth0"
        hostname = "t"
        uptime = 1

    try:
        st = storage_mod.Storage(os.path.join(tmpdir, "t.db"))
        st.init_db()
        now = int(time.time())
        st.insert_sample({"ts": now, "iface": "eth0", "rx_bytes": 1000, "tx_bytes": 2000,
                          "cpu": 1.0, "mem_used": 1, "mem_total": 2,
                          "disk_used": 3, "disk_total": 4})
        fc = FakeCollector()

        # ---- 装配（token + 默认安全配置） ----
        cfg = {"token": "sekrit", "bind": "0.0.0.0", "rate_limit": 60,
               "allow_ips": [], "allow_url_token": False}
        api_mod.configure(cfg, st, fc)
        app = create_app(cfg, st, fc)
        c = app.test_client()

        # ---- 安全响应头：API ----
        r = c.get("/api/status", headers={"X-Token": "sekrit"})
        h = r.headers
        check("API 200 且 ok", r.status_code == 200 and r.get_json()["ok"])
        check("X-Content-Type-Options: nosniff",
              h.get("X-Content-Type-Options") == "nosniff")
        check("X-Frame-Options: DENY", h.get("X-Frame-Options") == "DENY")
        check("Referrer-Policy: no-referrer",
              h.get("Referrer-Policy") == "no-referrer")
        check("Permissions-Policy 存在", bool(h.get("Permissions-Policy")))
        csp = h.get("Content-Security-Policy") or ""
        check("CSP script-src 'self'", "script-src 'self'" in csp)
        check("CSP style-src 'unsafe-inline'", "'unsafe-inline'" in csp)
        check("CSP img-src data:", "img-src 'self' data:" in csp)
        check("CSP object-src 'none'", "object-src 'none'" in csp)
        check("CSP frame-ancestors 'none'", "frame-ancestors 'none'" in csp)
        check("API Cache-Control: no-store", h.get("Cache-Control") == "no-store")

        # ---- 安全响应头：静态页 ----
        r = c.get("/")
        h = r.headers
        check("GET / 200", r.status_code == 200)
        check("静态页也有 CSP/XFO/nosniff",
              "Content-Security-Policy" in h
              and h.get("X-Frame-Options") == "DENY"
              and h.get("X-Content-Type-Options") == "nosniff")
        check("静态页 Cache-Control 放宽（非 no-store）",
              h.get("Cache-Control") != "no-store")
        r = c.get("/static/js/app.js")
        check("static js 200 + nosniff", r.status_code == 200
              and r.headers.get("X-Content-Type-Options") == "nosniff")
        check("static Cache-Control public",
              (r.headers.get("Cache-Control") or "").startswith("public"))

        # ---- 鉴权（默认仅 X-Token） ----
        r = c.get("/api/status")
        check("无 token → 401 统一体",
              r.status_code == 401
              and r.get_json() == {"ok": False, "error": "unauthorized"})
        r = c.get("/api/status?token=sekrit")
        check("?token= 默认拒绝 401", r.status_code == 401)
        r = c.get("/api/status", headers={"X-Token": "wrong"})
        check("错误 X-Token → 401", r.status_code == 401)
        r = c.get("/api/status", headers={"X-Token": "sekrit"})
        check("正确 X-Token → 200", r.status_code == 200)

        # allow_url_token=true 兼容旧行为
        cfg2 = dict(cfg)
        cfg2["allow_url_token"] = True
        api_mod.configure(cfg2, st, fc)
        r = c.get("/api/status?token=sekrit")
        check("allow_url_token=true ?token= → 200", r.status_code == 200)
        api_mod.configure(cfg, st, fc)

        # ---- 参数校验 ----
        r = c.get("/api/history?iface=bad/iface&limit=1", headers={"X-Token": "sekrit"})
        check("iface 非法字符 → 400 invalid iface",
              r.status_code == 400 and r.get_json()["error"] == "invalid iface")
        r = c.get("/api/history?iface=%s&limit=1" % ("a" * 65),
                  headers={"X-Token": "sekrit"})
        check("iface 超长 65 → 400", r.status_code == 400)
        r = c.get("/api/history?iface=eth0.v2_3-x&limit=1", headers={"X-Token": "sekrit"})
        check("iface 合法字符集 → 200", r.status_code == 200)
        r = c.get("/api/traffic/daily?month=2026-1", headers={"X-Token": "sekrit"})
        check("month=2026-1 非严格 YYYY-MM → 400", r.status_code == 400)
        r = c.get("/api/traffic/daily?month=2026-01", headers={"X-Token": "sekrit"})
        check("month=2026-01 → 200", r.status_code == 200)
        r = c.get("/api/traffic/daily?month=2026-13", headers={"X-Token": "sekrit"})
        check("month=2026-13 → 400", r.status_code == 400)

        # ---- Host 头校验 ----
        r = c.get("/api/status", headers={"X-Token": "sekrit", "Host": "evil.example.com"})
        check("Host 未知域名 → 400 invalid host",
              r.status_code == 400 and r.get_json()["error"] == "invalid host")
        r = c.get("/", headers={"Host": "evil.example.com"})
        check("静态页 Host 未知域名 → 400", r.status_code == 400)
        r = c.get("/api/status", headers={"X-Token": "sekrit", "Host": "127.0.0.1:8080"})
        check("Host IP 字面量放行 → 200", r.status_code == 200)
        r = c.get("/", headers={"Host": "localhost"})
        check("Host localhost 放行 → 200", r.status_code == 200)
        r = c.get("/", headers={"Host": "evil.com@127.0.0.1:8080"})
        check("Host 含 userinfo（@）→ 400", r.status_code == 400)

        # werkzeug test_client 构造 environ 时对非法端口直接抛 ValueError
        # （请求到不了应用层即被拒）；两种路径都算"拒绝"。
        def _host_code(host):
            try:
                return c.get("/", headers={"Host": host}).status_code
            except ValueError:
                return 400

        check("Host 端口越界 → 拒绝（400/客户端 ValueError）",
              _host_code("127.0.0.1:99999") == 400)
        check("Host 端口非数字 → 拒绝（400/客户端 ValueError）",
              _host_code("127.0.0.1:abc") == 400)

        # ---- 404/405 不泄堆栈 ----
        r = c.get("/api/nonexistent", headers={"X-Token": "sekrit"})
        check("未知 API 404 JSON", r.status_code == 404 and r.get_json()["ok"] is False)
        r = c.post("/api/status", headers={"X-Token": "sekrit"})
        check("POST 405 JSON", r.status_code == 405 and r.get_json()["ok"] is False)

        # ---- HSTS 仅 HTTPS ----
        r = c.get("/api/status", headers={"X-Token": "sekrit"},
                  environ_overrides={"wsgi.url_scheme": "https"})
        check("HTTPS 下发 HSTS",
              (r.headers.get("Strict-Transport-Security") or "").startswith("max-age="))
        r = c.get("/api/status", headers={"X-Token": "sekrit"})
        check("HTTP 不下发 HSTS", "Strict-Transport-Security" not in r.headers)

        # ---- 限流（独立 app 避免污染） ----
        api_mod.configure({"token": "", "rate_limit": 3}, st, fc)
        arl = create_app({"token": "", "rate_limit": 3, "bind": "0.0.0.0"}, st, fc)
        crl = arl.test_client()
        codes = [crl.get("/api/status").status_code for _ in range(4)]
        check("限流前 3 次 200 第 4 次 429",
              codes[:3] == [200, 200, 200] and codes[3] == 429)
        r = crl.get("/api/status")
        check("429 JSON {ok:false,error:rate_limited}",
              r.status_code == 429
              and r.get_json() == {"ok": False, "error": "rate_limited"})
        api_mod.configure({"token": "", "rate_limit": 0}, st, fc)
        a0 = create_app({"token": "", "rate_limit": 0, "bind": "0.0.0.0"}, st, fc)
        c0 = a0.test_client()
        check("rate_limit=0 关闭限流",
              all(c0.get("/api/status").status_code == 200 for _ in range(5)))

        # ---- 白名单（独立 app + remote_addr 模拟） ----
        wl_cfg = {"token": "", "allow_ips": ["192.0.2.0/24", "2001:db8::/32"],
                  "bind": "0.0.0.0"}
        api_mod.configure(wl_cfg, st, fc)
        awl = create_app(wl_cfg, st, fc)
        cwl = awl.test_client()
        r = cwl.get("/api/status", environ_overrides={"REMOTE_ADDR": "198.51.100.9"})
        check("白名单外 IPv4 → 403 forbidden",
              r.status_code == 403
              and r.get_json() == {"ok": False, "error": "forbidden"})
        r = cwl.get("/api/status", environ_overrides={"REMOTE_ADDR": "192.0.2.9"})
        check("白名单内 IPv4（CIDR）→ 200", r.status_code == 200)
        r = cwl.get("/api/status", environ_overrides={"REMOTE_ADDR": "2001:db8::9"})
        check("白名单内 IPv6 → 200", r.status_code == 200)
        r = cwl.get("/api/status", environ_overrides={"REMOTE_ADDR": "2001:db9::9"})
        check("白名单外 IPv6 → 403", r.status_code == 403)
        r = cwl.get("/api/status", environ_overrides={"REMOTE_ADDR": "::ffff:192.0.2.9"})
        check("IPv4-mapped IPv6 命中 IPv4 条目 → 200", r.status_code == 200)

        # ---- 代理场景（trusted_proxy + XFF） ----
        px_cfg = {"token": "", "allow_ips": ["192.0.2.1"], "trusted_proxy": "10.0.0.1",
                  "bind": "0.0.0.0"}
        api_mod.configure(px_cfg, st, fc)
        apx = create_app(px_cfg, st, fc)
        cpx = apx.test_client()
        r = cpx.get("/api/status", environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
                    headers={"X-Forwarded-For": "192.0.2.1"})
        check("信任代理 XFF 命中白名单 → 200", r.status_code == 200)
        r = cpx.get("/api/status", environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
                    headers={"X-Forwarded-For": "198.51.100.1"})
        check("信任代理 XFF 未命中 → 403", r.status_code == 403)
        r = cpx.get("/api/status", environ_overrides={"REMOTE_ADDR": "10.0.0.9"},
                    headers={"X-Forwarded-For": "192.0.2.1"})
        check("非信任来源伪造 XFF 无效 → 403", r.status_code == 403)

        st.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # ---- 日志脱敏（纯函数，无需 app） ----
    try:
        f = _QueryRedactFilter()
        rec = logging.LogRecord("werkzeug", logging.INFO, __file__, 1,
                                '"GET /api/status?token=sekrit&a=1 HTTP/1.1" 200 -',
                                (), None)
        f.filter(rec)
        msg = rec.getMessage()
        check("access log query 脱敏（token 不出日志）",
              "?token=sekrit" not in msg and "?redacted" in msg)
        rec2 = logging.LogRecord("werkzeug", logging.INFO, __file__, 1,
                                 '"GET /static/js/app.js HTTP/1.1" 200 -', (), None)
        f.filter(rec2)
        check("无 query 日志原样",
              rec2.getMessage() == '"GET /static/js/app.js HTTP/1.1" 200 -')
    except Exception as e:                    # 防御：日志脱敏断言失败不掩蔽主结果
        check("日志脱敏断言异常: %s" % e, False)

    print("\napp self-test: %d/%d passed" % (sum(ok), len(ok)))
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main())
