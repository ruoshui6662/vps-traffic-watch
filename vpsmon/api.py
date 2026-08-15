# -*- coding: utf-8 -*-
"""vpsmon.api — Flask Blueprint：6 个 API 端点 + 安全控制（SPEC §6 + SECURITY §4）。

- 成功响应统一 {"ok": true, "data": ...}；失败 {"ok": false, "error": "..."}；
- ts 为 Unix 秒；字节单位一律 bytes；time 为服务器本地时区展示字段；
- 多网卡端点接受可选 ?iface=，缺省 = 当前所选网卡（collector.selected）；
- 安全控制（SECURITY.md §4，全部可配置，向后兼容）：
  * 鉴权：token 非空时校验 X-Token 头（hmac.compare_digest 恒定时间比较）；
    URL ?token= 默认拒绝（allow_url_token=true 时兼容旧行为）；鉴权失败一律
    401 {"ok":false,"error":"unauthorized"}，不区分缺失/错误、不泄露数据；
  * 限流：按来源 IP 内存滑动窗口（rate_limit 次/分钟/IP，0=关闭），超限
    429 {"ok":false,"error":"rate_limited"}；
  * 白名单：allow_ips（IP/CIDR，IPv4/IPv6；trusted_proxy 场景采信 XFF 首段），
    非空时仅白名单内 IP 可访问 /api/*，其余 403 {"ok":false,"error":"forbidden"}；
  * 参数校验：iface 字符集 ^[A-Za-z0-9._-]{1,64}$，非法 400。
  * 检查顺序：白名单(403) → 限流(429) → 鉴权(401) → 参数校验(400)。
- psutil 缺失/失败时 status/interfaces 降级：自动切换 /proc 采集后端
  （procmetrics，SPEC §13.2.1），仍失败回退到库内最新样本与运行态属性。

架构（SPEC §13.2.2）：6 端点逻辑为**框架无关纯处理器** handle_*（Flask 蓝图与
stdlib Handler 共用），安全原语抽取到 security.py（鉴权/限流/白名单/参数边界），
本模块 Flask 蓝图仅作薄适配：request → security 安全门 → 纯处理器 → jsonify。

Flask 未安装时本模块仍可导入（create_blueprint 调用时才要求 Flask），
便于 py_compile、静态检查与 stdlib 后端共用；自检：python -m vpsmon.api（需 Flask）。
"""

import functools
import logging
import os
import time
from datetime import datetime

try:
    from flask import Blueprint, jsonify, request
    _FLASK = True
except ImportError:                          # 开发/静态检查环境可无 Flask
    Blueprint = jsonify = request = None     # type: ignore[assignment]
    _FLASK = False

try:
    import psutil
except ImportError:
    psutil = None                            # type: ignore[assignment]

from .collector import _VIRT_PREFIXES
from . import storage as storage_mod
from vpsmon import procmetrics as procmetrics_mod
from vpsmon import security as security_mod

log = logging.getLogger("vpsmon.api")

_cfg = {}
_storage = None
_collector = None


def configure(cfg, storage, collector=None) -> None:
    """app.py 启动时注入：配置、存储、采集器运行态。"""
    global _cfg, _storage, _collector
    _cfg = dict(cfg or {})
    _storage = storage
    _collector = collector


# ---------------------------------------------------------------- 工具

def resolve_iface(params, collector) -> str:
    """?iface= 缺省 = 当前所选网卡（SPEC §6.0）；均无 → ""。

    params: 已解析的请求参数映射（Flask request.args 或 stdlib parse_qs 首值，
    均支持 .get(name) 返回首值/None）。
    """
    iface = (params.get("iface") or "").strip()
    if iface:
        return iface
    if collector is not None:
        sel = getattr(collector, "selected", None)
        if sel:
            return sel
    return ""


# ---------------------------------------------------------------- 纯处理器
# SPEC §13.2.2：6 端点纯函数 handle_*（框架无关，Flask 蓝图与 stdlib Handler
# 共同调用）。安全门（白名单 403 → 限流 429 → 鉴权 401 → iface 400）由适配层
# 执行，处理器只负责取数组装。返回 (status_code, body)，body 字段逐条遵守
# SPEC §6.0–§6.7（含空库形状、time 展示字段、stale_sec、db_bytes 等）。

def handle_status(cfg, storage, collector, iface):
    """/api/status：实时指标（psutil 或 /proc 后端）→ 回退库内样本与运行态。"""
    server_time = int(time.time())
    backend = procmetrics_mod.metrics_backend(psutil_mod=psutil)
    cpu = mem = disk = uptime = None
    rx_bytes = tx_bytes = None
    if backend is not None:
        try:
            cpu = backend.cpu_percent()
        except Exception:
            log.warning("status: cpu_percent 失败", exc_info=True)
        try:
            mem = backend.meminfo()
        except Exception:
            log.warning("status: virtual_memory 失败", exc_info=True)
        try:
            disk = backend.disk_usage("/")
        except Exception:
            log.warning("status: disk_usage 失败", exc_info=True)
        try:
            uptime = backend.uptime()
        except Exception:
            log.warning("status: boot_time 失败", exc_info=True)
        if iface:
            try:
                io = backend.net_counters().get(iface)
                if io is not None:
                    rx_bytes = procmetrics_mod.io_bytes(io, "bytes_recv", "rx_bytes")
                    tx_bytes = procmetrics_mod.io_bytes(io, "bytes_sent", "tx_bytes")
            except Exception:
                log.warning("status: net_io_counters 失败", exc_info=True)
    ls = storage.latest_sample(iface) if storage is not None and iface else None
    if cpu is None:
        cpu = ls["cpu"] if ls else 0.0
    if mem is None:
        mem = {"used": ls["mem_used"], "total": ls["mem_total"]} if ls \
            else {"used": 0, "total": 0}
    if disk is None:
        disk = {"used": ls["disk_used"], "total": ls["disk_total"]} if ls \
            else {"used": 0, "total": 0}
    if uptime is None:
        uptime = getattr(collector, "uptime", None) if collector else None
    if rx_bytes is None:
        rx_bytes = ls["rx_bytes"] if ls else None
        tx_bytes = ls["tx_bytes"] if ls else None
    meta = storage.status_meta(iface) if storage is not None \
        else {"latest_ts": None, "sample_count": 0}
    live = storage.live(iface, 5) if storage is not None \
        else {"rx_rate": 0.0, "tx_rate": 0.0}
    return 200, {"ok": True, "data": {
        "server_time": server_time,
        "uptime": uptime,
        "cpu": cpu,
        "mem": mem,
        "disk": disk,
        "iface": iface,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "hostname": getattr(collector, "hostname", "") if collector else "",
        "rx_rate": live["rx_rate"],
        "tx_rate": live["tx_rate"],
        "latest_ts": meta["latest_ts"],
        "sample_count": meta["sample_count"],
        "db_bytes": storage.db_size() if storage is not None else 0,
    }}


def handle_monthly(cfg, storage, collector, iface):
    """/api/traffic/monthly：固定 12 项升序，末项当月。"""
    months = storage.monthly(iface) if storage is not None else []
    return 200, {"ok": True, "data": {"iface": iface, "months": months}}


def handle_daily(cfg, storage, collector, iface, month):
    """/api/traffic/daily：month 非法 → 400（错误体与 Flask 版逐字一致）。"""
    if not security_mod.valid_month(month):
        return 400, {"ok": False, "error": "invalid month, expect YYYY-MM"}
    try:
        days = storage.daily(iface, month) if storage is not None else []
    except ValueError:                       # 防御：storage 解析兜底
        return 400, {"ok": False, "error": "invalid month, expect YYYY-MM"}
    return 200, {"ok": True, "data": {"month": month, "iface": iface, "days": days}}


def handle_live(cfg, storage, collector, iface, minutes_raw=None):
    """/api/traffic/live：速率 + 时间窗序列；minutes 越界/非法回退 30。"""
    minutes = security_mod.clamp_int(minutes_raw, 30, 5, 1440)
    d = storage.live(iface, minutes) if storage is not None \
        else {"rx_rate": 0.0, "tx_rate": 0.0, "series": []}
    latest = None
    if storage is not None:
        latest = storage.status_meta(iface)["latest_ts"]
    return 200, {"ok": True, "data": {
        "iface": iface,
        "rx_rate": d["rx_rate"],
        "tx_rate": d["tx_rate"],
        "stale_sec": (int(time.time()) - latest) if latest is not None else None,
        "series": d["series"],
    }}


def handle_history(cfg, storage, collector, iface, limit_raw=None):
    """/api/history：最近 limit 条明细（倒序）；limit 越界/非法回退 100。"""
    limit = security_mod.clamp_int(limit_raw, 100, 1, 1000)
    samples = storage.history(iface, limit) if storage is not None else []
    for s in samples:                     # 展示辅助字段（本地时区，SPEC §6.0）
        s["time"] = datetime.fromtimestamp(s["ts"]).strftime("%Y-%m-%d %H:%M:%S")
    return 200, {"ok": True, "data": {"iface": iface, "samples": samples}}


def handle_interfaces(cfg, storage, collector):
    """/api/interfaces：实时网卡（过滤 lo/虚拟前缀）→ 后端不可用时库内兜底。"""
    # selected 未确定（空库/后端缺失/首轮采样前）时规范为 ""（SPEC §6.7 字段为字符串）
    selected = (getattr(collector, "selected", "") or "") if collector is not None else ""
    result = []
    backend = procmetrics_mod.metrics_backend(psutil_mod=psutil)
    if backend is not None:
        try:
            counters = backend.net_counters()
            for name in sorted(counters, key=lambda n: -(
                    procmetrics_mod.io_bytes(counters[n], "bytes_recv", "rx_bytes")
                    + procmetrics_mod.io_bytes(counters[n], "bytes_sent", "tx_bytes"))):
                if name == "lo" or name.startswith(_VIRT_PREFIXES):
                    continue
                io = counters[name]
                result.append({
                    "name": name,
                    "rx_bytes": procmetrics_mod.io_bytes(io, "bytes_recv", "rx_bytes"),
                    "tx_bytes": procmetrics_mod.io_bytes(io, "bytes_sent", "tx_bytes"),
                    "is_selected": name == selected,
                })
        except Exception:
            log.warning("interfaces: net_io_counters 失败", exc_info=True)
    if not result and storage is not None:   # 后端不可用 → 库内已知网卡兜底
        for r in storage.list_ifaces_with_counts():
            result.append({"name": r["iface"], "rx_bytes": r["rx_bytes"],
                           "tx_bytes": r["tx_bytes"],
                           "is_selected": r["iface"] == selected})
    return 200, {"ok": True, "data": {"selected": selected, "interfaces": result}}


# ---------------------------------------------------------------- Flask 适配层
# SPEC §13.2.2：蓝图 = 薄适配层（request → security 安全门 → 纯处理器 → jsonify）。

def _require_token(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not security_mod.authenticate(_cfg, request.headers,
                                         request.args.get("token")):
            # 统一 401：不区分缺失/错误/参数位置，不泄露任何数据
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return view(*args, **kwargs)
    return wrapped


def _validate_iface(view):
    """iface 参数字符集白名单（SECURITY §4.8.4），复用 security.validate_iface。"""

    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not security_mod.validate_iface(request.args.get("iface")):
            return jsonify({"ok": False, "error": "invalid iface"}), 400
        return view(*args, **kwargs)
    return wrapped


def _params():
    """当前请求的已解析参数（None = 缺失；与 stdlib parse_qs 首值语义对齐）。"""
    return {
        "iface": request.args.get("iface"),
        "month": request.args.get("month"),
        "minutes": request.args.get("minutes"),
        "limit": request.args.get("limit"),
    }


# ---------------------------------------------------------------- 路由

def create_blueprint():
    """构建 API Blueprint（url_prefix=/api 由 app 注册时指定）。

    SPEC §13.2.2：薄适配层——request → security 安全门（白名单 403 → 限流 429
    → 视图内鉴权 401 → iface 400）→ 纯处理器 handle_* → jsonify。
    """
    if not _FLASK:
        raise RuntimeError("Flask 未安装：请先 pip install flask（生产由 requirements.txt 提供）")
    bp = Blueprint("api", __name__)

    # ---- 安全中间件（SECURITY §4.3 顺序：白名单 403 → 限流 429 → 视图内鉴权 401）----
    _rl = security_mod.SlidingWindowRateLimiter(security_mod.rate_limit_value(_cfg))

    @bp.before_request
    def _security_gate():
        ip = security_mod.client_ip(_cfg, request.remote_addr or "", request.headers)
        if not security_mod.ip_allowed(_cfg, ip):
            return jsonify({"ok": False, "error": "forbidden"}), 403
        if not _rl.allow(ip):
            return jsonify({"ok": False, "error": "rate_limited"}), 429
        return None

    @bp.route("/status", methods=["GET"])
    @_require_token
    @_validate_iface
    def status():
        params = _params()
        code, body = handle_status(_cfg, _storage, _collector,
                                   resolve_iface(params, _collector))
        return jsonify(body), code

    @bp.route("/traffic/monthly", methods=["GET"])
    @_require_token
    @_validate_iface
    def monthly():
        params = _params()
        code, body = handle_monthly(_cfg, _storage, _collector,
                                    resolve_iface(params, _collector))
        return jsonify(body), code

    @bp.route("/traffic/daily", methods=["GET"])
    @_require_token
    @_validate_iface
    def daily():
        params = _params()
        code, body = handle_daily(_cfg, _storage, _collector,
                                  resolve_iface(params, _collector), params["month"])
        return jsonify(body), code

    @bp.route("/traffic/live", methods=["GET"])
    @_require_token
    @_validate_iface
    def live():
        params = _params()
        code, body = handle_live(_cfg, _storage, _collector,
                                 resolve_iface(params, _collector), params["minutes"])
        return jsonify(body), code

    @bp.route("/history", methods=["GET"])
    @_require_token
    @_validate_iface
    def history():
        params = _params()
        code, body = handle_history(_cfg, _storage, _collector,
                                    resolve_iface(params, _collector), params["limit"])
        return jsonify(body), code

    @bp.route("/interfaces", methods=["GET"])
    @_require_token
    def interfaces():
        code, body = handle_interfaces(_cfg, _storage, _collector)
        return jsonify(body), code

    return bp


# ---------------------------------------------------------------- 自检

def _smoke_test() -> None:
    """冒烟：test_client 全端点形状 + 鉴权 + 参数边界 + 空库（需 Flask）。"""
    import calendar
    import shutil
    from datetime import date

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmpdir = os.path.join(root, "vpsmon_api_test_%d_%d"
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

    st = storage_mod.Storage(os.path.join(tmpdir, "t.db"))
    st.init_db()
    fake_col = FakeCollector()
    try:
        now = int(time.time())
        base = now - 200
        for i in range(4):
            st.insert_sample({
                "ts": base + i * 50, "iface": "eth0",
                "rx_bytes": 1000 + i * 100, "tx_bytes": 2000 + i * 100,
                "cpu": 10.0 + i, "mem_used": 1024, "mem_total": 2048,
                "disk_used": 4096, "disk_total": 8192,
            })
        st.insert_sample({"ts": now, "iface": "eth1", "rx_bytes": 99, "tx_bytes": 99,
                          "cpu": 5.0, "mem_used": 1, "mem_total": 2,
                          "disk_used": 3, "disk_total": 4})

        # ---- 无 token（用 app.create_app 装配，验证蓝图+错误处理+静态页兜底）----
        # 注意：python -m 运行时本模块名为 __main__，蓝图实际定义在 vpsmon.api
        # 实例内，configure 必须打到该实例（与 app_mod 共用同一 sys.modules 条目）。
        import sys
        import vpsmon.app as app_mod
        import vpsmon.api as api_pkg
        api_pkg.configure({}, st, fake_col)
        app = app_mod.create_app({}, st, fake_col)
        c = app.test_client()

        r = c.get("/api/status")
        j = r.get_json()
        check("status 200 且 ok", r.status_code == 200 and j["ok"])
        d = j["data"]
        check("status iface=eth0", d["iface"] == "eth0")
        check("status hostname/uptime 字段存在",
              d["hostname"] == "test-host" and d["uptime"] == 12345)
        check("status 计数来自最新样本",
              d["rx_bytes"] == 1300 and d["tx_bytes"] == 2300)
        check("status latest_ts=now-50 sample_count=4 db_bytes>0",
              d["latest_ts"] == now - 50 and d["sample_count"] == 4
              and d["db_bytes"] > 0)

        r = c.get("/api/traffic/monthly")
        j = r.get_json()
        cur_m = date.today().strftime("%Y-%m")
        check("monthly 固定 12 项且末项为当月",
              j["ok"] and len(j["data"]["months"]) == 12
              and j["data"]["months"][-1]["month"] == cur_m)
        check("monthly 当月 rx>0", j["data"]["months"][-1]["rx"] > 0)

        r = c.get("/api/traffic/daily?month=bad")
        j = r.get_json()
        check("daily 非法 month → 400", r.status_code == 400
              and j["ok"] is False and j["error"] == "invalid month, expect YYYY-MM")
        y, m = date.today().year, date.today().month
        r = c.get("/api/traffic/daily?month=%04d-%02d" % (y, m))
        j = r.get_json()
        check("daily 项数=当月天数", j["ok"]
              and len(j["data"]["days"]) == calendar.monthrange(y, m)[1])
        today = date.today().strftime("%Y-%m-%d")
        tday = [x for x in j["data"]["days"] if x["day"] == today][0]
        check("daily 今日 rx=300", tday["rx"] == 300 and tday["tx"] == 300)

        r = c.get("/api/traffic/live?minutes=9999")
        j = r.get_json()
        d = j["data"]
        check("live minutes 越界回退 30（series 非空 + stale≈50）",
              j["ok"] and len(d["series"]) >= 1
              and d["stale_sec"] is not None and 49 <= d["stale_sec"] <= 61)
        r = c.get("/api/traffic/live?minutes=abc")
        check("live minutes 非数字回退 30", r.get_json()["ok"])

        r = c.get("/api/history?limit=2")
        j = r.get_json()
        hs = j["data"]["samples"]
        check("history limit=2 倒序且含 time",
              j["ok"] and len(hs) == 2 and hs[0]["ts"] > hs[1]["ts"]
              and "time" in hs[0] and "rx_rate" in hs[0])
        r = c.get("/api/history?limit=0")
        check("history limit=0 回退 100", r.get_json()["ok"])

        r = c.get("/api/interfaces")
        j = r.get_json()
        names = [x["name"] for x in j["data"]["interfaces"]]
        check("interfaces 含 eth0/eth1 且 selected=eth0",
              j["data"]["selected"] == "eth0" and "eth0" in names and "eth1" in names
              and j["data"]["interfaces"][0]["is_selected"] is True)

        r = c.get("/api/nonexistent")
        check("未知路径 404 JSON", r.status_code == 404 and r.get_json()["ok"] is False)
        r = c.post("/api/status")
        check("POST 方法不允许 405 JSON",
              r.status_code == 405 and r.get_json()["ok"] is False)
        r = c.get("/")
        check("/ 路由可达（前端未交付时 404 JSON，已交付时 200）",
              r.status_code == 200 or (r.status_code == 404 and r.get_json()["ok"] is False))

        # ---- token 鉴权（SECURITY H2/H3：恒定时间比较；默认仅 X-Token 头）----
        api_pkg.configure({"token": "sekrit"}, st, fake_col)
        c2 = app.test_client()
        r = c2.get("/api/status")
        check("无 token → 401 统一体", r.status_code == 401
              and r.get_json() == {"ok": False, "error": "unauthorized"})
        r = c2.get("/api/status?token=sekrit")
        check("?token= 默认拒绝 401（allow_url_token=false）", r.status_code == 401)
        r = c2.get("/api/status?token=wrong")
        check("?token= 错误 → 401", r.status_code == 401)
        r = c2.get("/api/status", headers={"X-Token": "wrong"})
        check("错误 X-Token → 401", r.status_code == 401)
        r = c2.get("/api/status", headers={"X-Token": "sekrit"})
        check("X-Token 头通过", r.status_code == 200)
        api_pkg.configure({"token": "sekrit", "allow_url_token": True}, st, fake_col)
        r = c2.get("/api/status?token=sekrit")
        check("allow_url_token=true ?token= 兼容 200", r.status_code == 200)
        r = c2.get("/api/status", headers={"X-Token": "sekrit"})
        check("allow_url_token=true X-Token 仍通过", r.status_code == 200)
        api_pkg.configure({"token": "sekrit"}, st, fake_col)
        r = c2.get("/api/status?token=sekrit")
        check("恢复默认后 ?token= 再拒 401", r.status_code == 401)

        # ---- 安全响应头（API + 静态页，SECURITY M1/§4.6）----
        r = c2.get("/api/status", headers={"X-Token": "sekrit"})
        h = r.headers
        check("API 安全头 nosniff/DENY/no-referrer",
              h.get("X-Content-Type-Options") == "nosniff"
              and h.get("X-Frame-Options") == "DENY"
              and h.get("Referrer-Policy") == "no-referrer")
        csp = h.get("Content-Security-Policy") or ""
        check("CSP 工作值（self/unsafe-inline/data:/none）",
              "default-src 'self'" in csp and "script-src 'self'" in csp
              and "style-src 'self' 'unsafe-inline'" in csp
              and "img-src 'self' data:" in csp
              and "object-src 'none'" in csp and "frame-ancestors 'none'" in csp)
        check("API Cache-Control no-store", h.get("Cache-Control") == "no-store")
        r = c.get("/")
        h = r.headers
        check("静态页安全头 + 放宽缓存",
              h.get("X-Frame-Options") == "DENY"
              and h.get("X-Content-Type-Options") == "nosniff"
              and "Content-Security-Policy" in h
              and h.get("Cache-Control") != "no-store")
        r = c.get("/static/css/style.css")
        check("static 200 + nosniff", r.status_code == 200
              and r.headers.get("X-Content-Type-Options") == "nosniff")

        # ---- iface 参数校验（SECURITY §4.8.4）----
        r = c2.get("/api/history?iface=bad/iface&limit=1", headers={"X-Token": "sekrit"})
        check("iface 非法字符 → 400 invalid iface", r.status_code == 400
              and r.get_json()["error"] == "invalid iface")
        r = c2.get("/api/history?iface=%s&limit=1" % ("a" * 65),
                   headers={"X-Token": "sekrit"})
        check("iface 超长 65 → 400", r.status_code == 400)
        r = c2.get("/api/history?iface=eth0.v2_3-x&limit=1",
                   headers={"X-Token": "sekrit"})
        check("iface 合法字符集 → 200", r.status_code == 200)

        # ---- month 严格 YYYY-MM（01-12）----
        r = c2.get("/api/traffic/daily?month=2026-1", headers={"X-Token": "sekrit"})
        check("month=2026-1 非零填充 → 400", r.status_code == 400)
        r = c2.get("/api/traffic/daily?month=2026-01", headers={"X-Token": "sekrit"})
        check("month=2026-01 → 200", r.status_code == 200)

        # ---- 限流（独立 app 避免污染主 app 状态；SECURITY H4）----
        api_pkg.configure({"rate_limit": 3}, st, fake_col)
        arl = app_mod.create_app({"rate_limit": 3}, st, fake_col)
        crl = arl.test_client()
        codes = [crl.get("/api/status").status_code for _ in range(5)]
        check("限流前 3 次 200，第 4/5 次 429",
              codes[:3] == [200, 200, 200] and codes[3] == 429 and codes[4] == 429)
        r = crl.get("/api/status")
        check("429 JSON {ok:false,error:rate_limited}",
              r.status_code == 429
              and r.get_json() == {"ok": False, "error": "rate_limited"})
        api_pkg.configure({"rate_limit": 0}, st, fake_col)
        a0 = app_mod.create_app({"rate_limit": 0}, st, fake_col)
        c0 = a0.test_client()
        check("rate_limit=0 关闭限流",
              all(c0.get("/api/status").status_code == 200 for _ in range(5)))

        # ---- 白名单（独立 app + remote_addr 模拟；SECURITY H5）----
        wl_cfg = {"allow_ips": ["192.0.2.0/24", "2001:db8::/32"]}
        api_pkg.configure(wl_cfg, st, fake_col)
        awl = app_mod.create_app(wl_cfg, st, fake_col)
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

        # ---- 代理场景（trusted_proxy + XFF）----
        px_cfg = {"allow_ips": ["192.0.2.1"], "trusted_proxy": "10.0.0.1"}
        api_pkg.configure(px_cfg, st, fake_col)
        apx = app_mod.create_app(px_cfg, st, fake_col)
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

        # ---- Host 头校验（SECURITY §4.8.3，防 DNS rebinding）----
        api_pkg.configure({"token": "sekrit"}, st, fake_col)   # 恢复主配置（无白名单）
        r = c2.get("/api/status", headers={"X-Token": "sekrit", "Host": "evil.example.com"})
        check("Host 未知域名 → 400 invalid host", r.status_code == 400
              and r.get_json()["error"] == "invalid host")
        r = c2.get("/api/status", headers={"X-Token": "sekrit", "Host": "127.0.0.1:8080"})
        check("Host IP 字面量放行 → 200", r.status_code == 200)
        r = c2.get("/", headers={"Host": "localhost"})
        check("Host localhost 放行 → 200", r.status_code == 200)

        # ---- 日志脱敏过滤器（werkzeug access log 含 query，SECURITY M5）----
        f = app_mod._QueryRedactFilter()
        rec = logging.LogRecord("werkzeug", logging.INFO, __file__, 1,
                                '"GET /api/status?token=sekrit&a=1 HTTP/1.1" 200 -',
                                (), None)
        f.filter(rec)
        check("access log 查询串脱敏（token 不出日志）",
              "?token=sekrit" not in rec.getMessage() and "?redacted" in rec.getMessage())

        # ---- 空库（新库） ----
        st2 = storage_mod.Storage(os.path.join(tmpdir, "e.db"))
        st2.init_db()
        api_pkg.configure({}, st2, FakeCollector())
        c3 = app.test_client()
        j = c3.get("/api/status").get_json()["data"]
        check("空库 status latest_ts null / sample_count 0",
              j["latest_ts"] is None and j["sample_count"] == 0)
        j = c3.get("/api/traffic/monthly").get_json()["data"]
        check("空库 monthly 12 项全 0",
              len(j["months"]) == 12 and all(x["rx"] == 0 for x in j["months"]))
        j = c3.get("/api/traffic/live").get_json()["data"]
        check("空库 live 速率 0 / series 空",
              j["rx_rate"] == 0.0 and j["tx_rate"] == 0.0 and j["series"] == []
              and j["stale_sec"] is None)
        j = c3.get("/api/history").get_json()["data"]
        check("空库 history samples 空", j["samples"] == [])
        st2.close()
    finally:
        st.close()
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\napi smoke test: %d/%d passed" % (sum(ok), len(ok)))
    if not all(ok):
        raise SystemExit("api smoke test FAILED")


if __name__ == "__main__":
    if not _FLASK:
        print("Flask 未安装：跳过 api 冒烟测试（生产环境由 requirements.txt 提供）")
        raise SystemExit(0)
    _smoke_test()
