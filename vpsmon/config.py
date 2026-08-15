# -*- coding: utf-8 -*-
"""vpsmon.config — 配置加载、校验与默认值回退（SPEC §4 + SECURITY §4.8 加固项）。

加载顺序（§4.2）：
    1. --config 显式路径（优先级最高）；
    2. 环境变量 VPSMON_CONFIG 指向的路径；
    3. 探测 /var/lib/vpsmon/config.json → 当前工作目录 ./config.json；
    4. 均不存在 → 内置默认值（db 落在当前工作目录 ./vpsmon.db）。

读取后逐字段校验并回退默认值（不回写文件）；JSON 解析失败 → 日志 + 默认值，
不崩溃（便于首次启动）。db_path 推导 = 配置文件所在目录下 vpsmon.db，可被
配置文件内 db_path 或 --db 显式覆盖（§3 路径推导规则）。

安全相关字段（SECURITY.md §4，全部向后兼容新增）：
    bind            监听地址（默认 0.0.0.0；可设 127.0.0.1 纯本机）
    allow_ips       IP 白名单（数组；支持 1.2.3.4 / 10.0.0.0/8 / 2001:db8::/32，
                    非法条目丢弃；也接受逗号分隔字符串）
    rate_limit      限流次数/分钟/IP（默认 60；0 = 关闭）
    allow_url_token 是否允许 ?token= 查询参数鉴权（默认 false 仅认 X-Token 头）
    ssl_certfile/ssl_keyfile  TLS 证书/密钥（默认空 = 不启用；必须成对配置）
    trusted_proxy   信任的反代地址（默认空；配置后仅来自该地址的请求才采信
                    X-Forwarded-For 首段，用于限流/白名单的真实客户端 IP）
    debug           调试开关：即使配置为 true 也强制回退 false（生产禁止调试器）

仅依赖 stdlib。
"""

import ipaddress
import json
import logging
import os
import time
from typing import Optional

log = logging.getLogger("vpsmon.config")

DEFAULTS = {
    "port": 8080,
    "interval": 60,
    "token": "",
    "iface": "",
    "keep_days": 0,
    "bind": "0.0.0.0",
    "allow_ips": [],
    "rate_limit": 60,
    "allow_url_token": False,
    "ssl_certfile": "",
    "ssl_keyfile": "",
    "debug": False,
    "trusted_proxy": "",
}

# 探测顺序（SPEC §4.2.3）
PROBE_PATHS = (
    "/var/lib/vpsmon/config.json",
    "config.json",   # 相对当前工作目录
)

_TRUE_STR = {"true", "1", "yes", "on", "y"}
_FALSE_STR = {"false", "0", "no", "off", "n"}


def _coerce_int(name: str, value, default: int, lo: int, hi: Optional[int]) -> int:
    """校验整数字段：缺失/None → 默认；非法或越界 → 回退默认并打日志。"""
    if value is None:
        return default
    try:
        v = int(value)
    except (TypeError, ValueError):
        log.warning("配置字段 %s=%r 非法，回退 %s", name, value, default)
        return default
    if v < lo or (hi is not None and v > hi):
        log.warning("配置字段 %s=%r 越界 [%s, %s]，回退 %s",
                    name, value, lo, hi if hi is not None else "inf", default)
        return default
    return v


def _coerce_str(name: str, value, default: str) -> str:
    """字符串字段：缺失/None/空白 → 默认；其余 strip 后返回。"""
    if value is None:
        return default
    s = str(value).strip()
    if not s:
        log.warning("配置字段 %s 为空，回退 %r", name, default)
        return default
    return s


def _coerce_bool(name: str, value, default: bool) -> bool:
    """布尔字段：接受 bool / 0-1 / 常见字符串（true/false/yes/no/on/off/1/0）。"""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _TRUE_STR:
            return True
        if v in _FALSE_STR:
            return False
    log.warning("配置字段 %s=%r 非法，回退 %s", name, value, default)
    return default


def _coerce_allow_ips(value):
    """IP 白名单字段：list[IP/CIDR]；非法条目丢弃并打日志。也接受逗号分隔字符串。"""
    if value is None:
        return []
    if isinstance(value, str):
        value = [v.strip() for v in value.split(",") if v.strip()]
    elif isinstance(value, (list, tuple)):
        value = [str(v).strip() for v in value if str(v).strip()]
    else:
        log.warning("配置字段 allow_ips=%r 非法，回退 []", value)
        return []
    out = []
    for v in value:
        try:
            if "/" in v:
                ipaddress.ip_network(v, strict=False)
            else:
                ipaddress.ip_address(v.split("%", 1)[0])
            out.append(v)
        except ValueError:
            log.warning("配置字段 allow_ips 条目 %r 非法，已忽略", v)
    return out


def _resolve_config_path(cfg_path: Optional[str]) -> Optional[str]:
    """SPEC §4.2 配置来源解析。返回配置文件路径或 None。"""
    if cfg_path:
        return cfg_path
    env = os.environ.get("VPSMON_CONFIG")
    if env:
        return env
    for p in PROBE_PATHS:
        if os.path.isfile(p):
            return p
    return None


def load_config(cfg_path: Optional[str] = None) -> dict:
    """加载并校验配置，返回完整配置 dict（含推导出的 db_path）。

    cfg_path: --config 显式路径；None 时按 SPEC §4.2 自动解析。
    """
    path = _resolve_config_path(cfg_path)
    raw = {}
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError) as e:
            log.warning("配置文件 %s 解析失败（%s），使用默认配置", path, e)
            raw = {}
        if not isinstance(raw, dict):
            log.warning("配置文件 %s 顶层不是 JSON 对象，使用默认配置", path)
            raw = {}
    elif path:
        log.warning("配置文件 %s 不存在，使用默认配置", path)

    cfg = {
        "port": _coerce_int("port", raw.get("port"), DEFAULTS["port"], 1, 65535),
        "interval": _coerce_int("interval", raw.get("interval"), DEFAULTS["interval"], 5, 86400),
        "keep_days": _coerce_int("keep_days", raw.get("keep_days"), DEFAULTS["keep_days"], 0, None),
        "rate_limit": _coerce_int("rate_limit", raw.get("rate_limit"),
                                  DEFAULTS["rate_limit"], 0, None),
        "token": str(raw.get("token") or ""),
        "iface": str(raw.get("iface") or ""),
        "bind": _coerce_str("bind", raw.get("bind"), DEFAULTS["bind"]),
        "allow_ips": _coerce_allow_ips(raw.get("allow_ips")),
        "allow_url_token": _coerce_bool("allow_url_token", raw.get("allow_url_token"),
                                        DEFAULTS["allow_url_token"]),
        "trusted_proxy": _coerce_str("trusted_proxy", raw.get("trusted_proxy"),
                                     DEFAULTS["trusted_proxy"]),
        "ssl_certfile": _coerce_str("ssl_certfile", raw.get("ssl_certfile"),
                                    DEFAULTS["ssl_certfile"]),
        "ssl_keyfile": _coerce_str("ssl_keyfile", raw.get("ssl_keyfile"),
                                   DEFAULTS["ssl_keyfile"]),
        "debug": _coerce_bool("debug", raw.get("debug"), DEFAULTS["debug"]),
    }
    # TLS 必须成对配置；缺一半 → 整体回退关闭（避免半启用 TLS 的误解）
    if bool(cfg["ssl_certfile"]) != bool(cfg["ssl_keyfile"]):
        log.warning("配置字段 ssl_certfile/ssl_keyfile 必须成对配置，TLS 未启用")
        cfg["ssl_certfile"] = cfg["ssl_keyfile"] = ""
    # debug 守卫（SECURITY §4.8.1）：配置 true 也强制回退 false
    if cfg["debug"]:
        log.warning("配置字段 debug=true 已强制回退 false（生产环境禁止开启调试器）")
        cfg["debug"] = False

    # db_path 推导（SPEC §3）：显式 db_path > 配置文件同目录 vpsmon.db > 当前目录
    explicit = raw.get("db_path")
    if explicit:
        cfg["db_path"] = os.path.abspath(os.fspath(explicit))
    elif path:
        cfg["db_path"] = os.path.join(os.path.dirname(os.path.abspath(path)), "vpsmon.db")
    else:
        cfg["db_path"] = os.path.abspath("vpsmon.db")
    return cfg


def apply_overrides(cfg: dict, port=None, interval=None, db_path=None) -> dict:
    """CLI 覆盖（--port/--interval/--db），复用同一套校验回退规则。原地修改并返回。"""
    if port is not None:
        cfg["port"] = _coerce_int("--port", port, DEFAULTS["port"], 1, 65535)
    if interval is not None:
        cfg["interval"] = _coerce_int("--interval", interval, DEFAULTS["interval"], 5, 86400)
    if db_path:
        cfg["db_path"] = os.path.abspath(os.fspath(db_path))
    return cfg


# ---------------------------------------------------------------- 自检

def _self_test() -> None:
    """配置字段校验自检：默认值 / 合法值 / 非法回退 / 布尔字符串 / 白名单形式。"""
    import shutil
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmpdir = os.path.join(root, "vpsmon_config_test_%d_%d"
                          % (int(time.time()), os.getpid()))
    os.makedirs(tmpdir, exist_ok=True)
    ok = []

    def check(name, cond):
        ok.append(cond)
        print(("PASS  " if cond else "FAIL  ") + name)

    def write(p, obj):
        with open(p, "w", encoding="utf-8") as f:
            json.dump(obj, f)

    try:
        # 1) 默认值（文件不存在 → 全默认）
        cfg = load_config(os.path.join(tmpdir, "nonexistent.json"))
        check("默认 bind=0.0.0.0", cfg["bind"] == "0.0.0.0")
        check("默认 allow_ips=[]", cfg["allow_ips"] == [])
        check("默认 rate_limit=60", cfg["rate_limit"] == 60)
        check("默认 allow_url_token=False", cfg["allow_url_token"] is False)
        check("默认 ssl_certfile/keyfile 空", cfg["ssl_certfile"] == ""
              and cfg["ssl_keyfile"] == "")
        check("默认 debug=False", cfg["debug"] is False)
        check("默认 trusted_proxy=''", cfg["trusted_proxy"] == "")

        # 2) 合法值全解析
        p = os.path.join(tmpdir, "ok.json")
        write(p, {
            "bind": "127.0.0.1", "rate_limit": 10, "allow_url_token": True,
            "allow_ips": ["10.0.0.0/8", "2001:db8::/32", "1.2.3.4"],
            "ssl_certfile": "/x/cert.pem", "ssl_keyfile": "/x/key.pem",
            "trusted_proxy": "10.0.0.1", "debug": False,
        })
        cfg = load_config(p)
        check("bind=127.0.0.1 解析", cfg["bind"] == "127.0.0.1")
        check("rate_limit=10", cfg["rate_limit"] == 10)
        check("allow_url_token=True", cfg["allow_url_token"] is True)
        check("allow_ips 3 条（IPv4/IPv6/CIDR）全保留",
              cfg["allow_ips"] == ["10.0.0.0/8", "2001:db8::/32", "1.2.3.4"])
        check("ssl 成对保留", cfg["ssl_certfile"] == "/x/cert.pem"
              and cfg["ssl_keyfile"] == "/x/key.pem")
        check("trusted_proxy 保留", cfg["trusted_proxy"] == "10.0.0.1")

        # 3) 非法值回退
        p = os.path.join(tmpdir, "bad.json")
        write(p, {
            "bind": "", "rate_limit": "abc", "allow_url_token": "nope",
            "allow_ips": ["10.0.0.0/8", "999.1.1.1", "not-an-ip",
                          "2001:db8::/129", 42],
            "ssl_certfile": "/x/cert.pem",
            "debug": True, "port": 0, "interval": 3,
        })
        cfg = load_config(p)
        check("bind 空回退 0.0.0.0", cfg["bind"] == "0.0.0.0")
        check("rate_limit 非整数回退 60", cfg["rate_limit"] == 60)
        check("allow_url_token 非法回退 False", cfg["allow_url_token"] is False)
        check("allow_ips 仅保留合法条目", cfg["allow_ips"] == ["10.0.0.0/8"])
        check("ssl 缺 key 成对回退空", cfg["ssl_certfile"] == ""
              and cfg["ssl_keyfile"] == "")
        check("debug=true 强制回退 False", cfg["debug"] is False)
        check("port=0 回退 8080", cfg["port"] == 8080)
        check("interval=3 回退 60", cfg["interval"] == 60)

        # 4) 布尔字符串
        p = os.path.join(tmpdir, "bool.json")
        write(p, {"allow_url_token": "true", "debug": "false"})
        cfg = load_config(p)
        check("allow_url_token='true' → True", cfg["allow_url_token"] is True)
        check("debug='false' → False", cfg["debug"] is False)

        # 5) allow_ips 逗号分隔字符串形式
        p = os.path.join(tmpdir, "strips.json")
        write(p, {"allow_ips": "1.2.3.4, 10.0.0.0/8"})
        cfg = load_config(p)
        check("allow_ips 逗号字符串解析",
              cfg["allow_ips"] == ["1.2.3.4", "10.0.0.0/8"])

        # 6) 顶层非对象回退默认
        p = os.path.join(tmpdir, "list.json")
        write(p, [1, 2])
        cfg = load_config(p)
        check("顶层非对象回退默认",
              cfg["rate_limit"] == 60 and cfg["allow_ips"] == []
              and cfg["bind"] == "0.0.0.0")

        # 7) apply_overrides 不破坏新字段
        cfg = load_config(os.path.join(tmpdir, "ok.json"))
        apply_overrides(cfg, port=9000)
        check("apply_overrides 后新字段保留",
              cfg["port"] == 9000 and cfg["rate_limit"] == 10
              and cfg["allow_url_token"] is True)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\nconfig self-test: %d/%d passed" % (sum(ok), len(ok)))
    if not all(ok):
        raise SystemExit("config self-test FAILED")


if __name__ == "__main__":
    _self_test()
