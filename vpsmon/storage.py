# -*- coding: utf-8 -*-
"""vpsmon.storage — SQLite 存储与正增量聚合。

对应 SPEC §5 / §7 / §8.1 / §8.5 的实现：

- 只存内核累计计数（rx_bytes/tx_bytes），不存速率与区间流量；
- 一切速率与月度/日度流量由查询时在 Python 层基于相邻样本"正增量"推导，
  SQLite 只负责取数（线性扫描，样本量 52 万行/年亦毫秒级）；
- 采集线程是唯一写入者（INSERT OR REPLACE，主键 (ts, iface) 幂等）；
- 单连接 + check_same_thread=False + threading.Lock 保护全部访问；
- 空库时所有查询返回合法空结构，不抛异常；
- 天/月边界按服务器本地时区聚合（SPEC §8.5）。

本模块不依赖 Flask，可独立 import；`python -m vpsmon.storage` 可运行内置自检。
"""

import calendar
import os
import re
import sqlite3
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts         INTEGER NOT NULL,   -- Unix 时间戳（秒），UTC 基准
    iface      TEXT    NOT NULL,   -- 网卡名（如 eth0）
    rx_bytes   INTEGER NOT NULL,   -- 内核累计接收字节（单调不减）
    tx_bytes   INTEGER NOT NULL,   -- 内核累计发送字节（单调不减）
    cpu        REAL    NOT NULL,   -- 采集间隔内 CPU 平均使用率（%）
    mem_used   INTEGER NOT NULL,   -- 已用内存（字节）
    mem_total  INTEGER NOT NULL,   -- 总内存（字节）
    disk_used  INTEGER NOT NULL,   -- 已用磁盘（字节）
    disk_total INTEGER NOT NULL,   -- 总磁盘（字节）
    PRIMARY KEY (ts, iface)        -- 同一时刻同网卡唯一
);
"""

SAMPLE_COLS = [
    "ts", "iface", "rx_bytes", "tx_bytes", "cpu",
    "mem_used", "mem_total", "disk_used", "disk_total",
]


def _shift_month(year: int, month: int, delta: int):
    """返回 (year, month) 平移 delta 个月后的年月。"""
    idx = year * 12 + (month - 1) + delta
    return idx // 12, idx % 12 + 1


def _month_bounds(year: int, month: int):
    """本地时区某自然月的 [起始 ts, 结束 ts) 秒级边界。"""
    start_dt = datetime(year, month, 1)
    y2, m2 = _shift_month(year, month, 1)
    end_dt = datetime(y2, m2, 1)
    return int(start_dt.timestamp()), int(end_dt.timestamp())


_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def _parse_month(month: str):
    """解析 'YYYY-MM'（严格：4 位年 + 2 位零填充月，月份 01-12）。

    非法输入抛 ValueError（由 api 层映射为 400）。拒绝 '2026-1'/'26-01'/
    '202601' 等非规范写法（SECURITY 参数边界收紧）。
    """
    if not isinstance(month, str):
        raise ValueError("invalid month, expect YYYY-MM")
    if not _MONTH_RE.match(month):
        raise ValueError("invalid month, expect YYYY-MM")
    y, m = int(month[:4]), int(month[5:7])
    if y < 1 or y > 9999 or m < 1 or m > 12:
        raise ValueError("invalid month, expect YYYY-MM")
    return y, m


def _rate(cur_bytes: int, prev_bytes: int, cur_ts: int, prev_ts: int) -> float:
    """bytes/s；无前驱、时间差 <=0 或差值 <=0（计数器重置）→ 0.0（SPEC §8.4）。"""
    dt = cur_ts - prev_ts
    if dt <= 0:
        return 0.0
    db = cur_bytes - prev_bytes
    if db <= 0:
        return 0.0
    return db / float(dt)


class Storage:
    """SQLite 存储与查询。只接受 db_path，路径推导由 app.py 负责（SPEC §3）。"""

    def __init__(self, db_path: str):
        self.db_path = os.fspath(db_path)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)  # 数据目录不存在时自动创建
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,   # 采集线程写 + API 线程读共享单连接
            isolation_level=None,      # 自动提交，WAL 下低写放大
        )
        self._conn.row_factory = sqlite3.Row

    # ------------------------------------------------------------------ 写

    def init_db(self) -> None:
        """建表 / WAL / 索引（幂等，可重复调用）。"""
        with self._lock:
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute(SCHEMA)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_samples_iface_ts ON samples(iface, ts)"
            )

    def insert_sample(self, rec: Dict) -> None:
        """写入一条采样（采集线程唯一写入者；INSERT OR REPLACE 幂等）。

        rec 必须含全部 9 个字段：ts/iface/rx_bytes/tx_bytes/cpu/
        mem_used/mem_total/disk_used/disk_total。
        """
        missing = [k for k in SAMPLE_COLS if k not in rec]
        if missing:
            raise ValueError("sample missing keys: %s" % ", ".join(missing))
        sql = (
            "INSERT OR REPLACE INTO samples "
            "(ts, iface, rx_bytes, tx_bytes, cpu, mem_used, mem_total, "
            " disk_used, disk_total) VALUES (?,?,?,?,?,?,?,?,?)"
        )
        with self._lock:
            self._conn.execute(sql, tuple(rec[k] for k in SAMPLE_COLS))

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # ------------------------------------------------------------ 核心算法

    def _window_deltas(self, iface: str, t0: int, t1: int) -> List:
        """区间 [t0, t1) 内样本的正增量列表 [(ts, drx, dtx), ...]，ts 升序。

        每个样本与其"数据库全局前驱"（同 iface、ts 严格更小的最近一行，可能落在
        区间外）做差；Δ>0 才计入，Δ<=0 视为计数器重置/网卡更换而丢弃（SPEC §8.1）。
        区间第一个样本的前驱在区间外属正常：其跨边界增量计入终点所在天/月。
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, rx_bytes, tx_bytes FROM samples "
                "WHERE iface=? AND ts>=? AND ts<? ORDER BY ts ASC",
                (iface, t0, t1),
            ).fetchall()
            prev = None
            if rows:
                p = self._conn.execute(
                    "SELECT ts, rx_bytes, tx_bytes FROM samples "
                    "WHERE iface=? AND ts<? ORDER BY ts DESC LIMIT 1",
                    (iface, rows[0]["ts"]),
                ).fetchone()
                if p is not None:
                    prev = (p["ts"], p["rx_bytes"], p["tx_bytes"])
        out = []
        for r in rows:
            if prev is not None:
                drx = r["rx_bytes"] - prev[1]
                dtx = r["tx_bytes"] - prev[2]
            else:
                drx = dtx = 0
            if drx > 0 or dtx > 0:
                out.append((r["ts"], drx if drx > 0 else 0, dtx if dtx > 0 else 0))
            prev = (r["ts"], r["rx_bytes"], r["tx_bytes"])
        return out

    # ------------------------------------------------------------------ 读

    def latest_sample(self, iface: str) -> Optional[Dict]:
        """最新一条样本；空库返回 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM samples WHERE iface=? ORDER BY ts DESC LIMIT 1",
                (iface,),
            ).fetchone()
        return dict(row) if row else None

    def recent_samples(self, iface: str, limit: int = 100) -> List[Dict]:
        """最近 limit 条样本，按 ts 倒序（最新在前）；空库返回 []。"""
        limit = int(limit) if limit else 100
        if limit < 1:
            limit = 100
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM samples WHERE iface=? ORDER BY ts DESC LIMIT ?",
                (iface, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def monthly(self, iface: str) -> List[Dict]:
        """最近 12 个自然月流量（升序，固定 12 项，无数据补 0）。

        每项 {"month": "YYYY-MM", "rx": int, "tx": int}，单位为字节。
        最后一项为当月（含进行中的部分月）。
        """
        now = datetime.now()
        months = []
        for i in range(11, -1, -1):
            y, m = _shift_month(now.year, now.month, -i)
            t0, t1 = _month_bounds(y, m)
            rx = tx = 0
            for _ts, drx, dtx in self._window_deltas(iface, t0, t1):
                rx += drx
                tx += dtx
            months.append({"month": "%04d-%02d" % (y, m), "rx": rx, "tx": tx})
        return months

    def daily(self, iface: str, month: str) -> List[Dict]:
        """指定月（YYYY-MM）每日流量，固定当月全部天数，无数据补 0。

        每项 {"day": "YYYY-MM-DD", "rx": int, "tx": int}。
        增量归属规则：样本与其全局前驱的增量计入终点样本 ts 所在那天（SPEC §6.4）。
        非法 month 抛 ValueError；空库返回全 0 天数列表。
        """
        y, m = _parse_month(month)
        t0, t1 = _month_bounds(y, m)
        ndays = calendar.monthrange(y, m)[1]
        rx_by_day = [0] * (ndays + 1)   # 下标 1..ndays
        tx_by_day = [0] * (ndays + 1)
        for ts, drx, dtx in self._window_deltas(iface, t0, t1):
            day = datetime.fromtimestamp(ts).day
            rx_by_day[day] += drx
            tx_by_day[day] += dtx
        return [
            {"day": "%04d-%02d-%02d" % (y, m, d),
             "rx": rx_by_day[d],
             "tx": tx_by_day[d]}
            for d in range(1, ndays + 1)
        ]

    def live(self, iface: str, minutes: int = 30) -> Dict:
        """实时速率与近期趋势（SPEC §6.5）。

        返回 {"rx_rate", "tx_rate", "series"}：rx/tx_rate 由最近两个样本推导；
        series 为时间窗内 [now-minutes*60, now] 升序速率序列，首点无前驱 → 0.0。
        空库 → 0.0/0.0/[]。
        """
        minutes = int(minutes) if minutes else 30
        if minutes <= 0:
            minutes = 30
        now = int(time.time())
        t0 = now - minutes * 60
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, rx_bytes, tx_bytes FROM samples "
                "WHERE iface=? AND ts>=? AND ts<=? ORDER BY ts ASC",
                (iface, t0, now),
            ).fetchall()
            last_two = self._conn.execute(
                "SELECT ts, rx_bytes, tx_bytes FROM samples "
                "WHERE iface=? ORDER BY ts DESC LIMIT 2",
                (iface,),
            ).fetchall()
        series = []
        prev = None
        for r in rows:
            if prev is None:
                series.append({"ts": r["ts"], "rx_rate": 0.0, "tx_rate": 0.0})
            else:
                series.append({
                    "ts": r["ts"],
                    "rx_rate": _rate(r["rx_bytes"], prev[1], r["ts"], prev[0]),
                    "tx_rate": _rate(r["tx_bytes"], prev[2], r["ts"], prev[0]),
                })
            prev = (r["ts"], r["rx_bytes"], r["tx_bytes"])
        rx_rate = tx_rate = 0.0
        if len(last_two) == 2:
            newer, older = last_two[0], last_two[1]
            rx_rate = _rate(newer["rx_bytes"], older["rx_bytes"],
                            newer["ts"], older["ts"])
            tx_rate = _rate(newer["tx_bytes"], older["tx_bytes"],
                            newer["ts"], older["ts"])
        return {"rx_rate": rx_rate, "tx_rate": tx_rate, "series": series}

    def history(self, iface: str, limit: int = 100) -> List[Dict]:
        """最近 limit 条样本明细（按 ts 倒序，最新在前）。

        每条含 rx_rate/tx_rate：该样本与其全局前驱的速率（无前驱 → 0.0）。
        为让窗口最老样本也有真实速率，取数时多取 1 条作前驱。空库 → []。
        """
        limit = int(limit) if limit else 100
        if limit < 1:
            limit = 100
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, rx_bytes, tx_bytes, cpu, mem_used, mem_total, "
                "       disk_used, disk_total "
                "FROM samples WHERE iface=? ORDER BY ts DESC LIMIT ?",
                (iface, limit + 1),
            ).fetchall()
        if len(rows) > limit:
            extra = rows[-1]                       # 窗口外的全局前驱
            disp = list(reversed(rows[:-1]))       # 升序
        else:
            extra = None
            disp = list(reversed(rows))
        out = []
        prev = extra
        for r in disp:
            if prev is None:
                rrate = trate = 0.0
            else:
                rrate = _rate(r["rx_bytes"], prev[1], r["ts"], prev[0])
                trate = _rate(r["tx_bytes"], prev[2], r["ts"], prev[0])
            out.append({
                "ts": r["ts"],
                "rx_bytes": r["rx_bytes"],
                "tx_bytes": r["tx_bytes"],
                "rx_rate": rrate,
                "tx_rate": trate,
                "cpu": r["cpu"],
                "mem_used": r["mem_used"],
                "mem_total": r["mem_total"],
                "disk_used": r["disk_used"],
                "disk_total": r["disk_total"],
            })
            prev = (r["ts"], r["rx_bytes"], r["tx_bytes"])
        out.reverse()                              # 倒序：最新在前
        return out

    def cpu_mem_history(self, iface: str, minutes: int = 30) -> List[Dict]:
        """时间窗内 CPU/内存序列（ts 升序），每条 {ts, cpu, mem_used, mem_total}。"""
        minutes = int(minutes) if minutes else 30
        if minutes <= 0:
            minutes = 30
        now = int(time.time())
        t0 = now - minutes * 60
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, cpu, mem_used, mem_total FROM samples "
                "WHERE iface=? AND ts>=? ORDER BY ts ASC",
                (iface, t0),
            ).fetchall()
        return [dict(r) for r in rows]

    def status_meta(self, iface: str) -> Dict:
        """最新样本时间与样本数：{"latest_ts": int|None, "sample_count": int}。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(ts) AS latest_ts, COUNT(*) AS cnt "
                "FROM samples WHERE iface=?",
                (iface,),
            ).fetchone()
        return {"latest_ts": row["latest_ts"], "sample_count": row["cnt"]}

    def list_ifaces_with_counts(self) -> List[Dict]:
        """库内出现过的网卡（按累计字节降序），每条含最新累计计数与样本数。"""
        sql = (
            "SELECT s.iface AS iface, s.rx_bytes AS rx_bytes, "
            "       s.tx_bytes AS tx_bytes, s.ts AS latest_ts, c.cnt AS count "
            "FROM samples s "
            "JOIN (SELECT iface, COUNT(*) AS cnt, MAX(ts) AS mts "
            "      FROM samples GROUP BY iface) c "
            "  ON s.iface = c.iface AND s.ts = c.mts "
            "ORDER BY (s.rx_bytes + s.tx_bytes) DESC"
        )
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        return [dict(r) for r in rows]

    def db_size(self) -> int:
        """vpsmon.db 文件大小（字节）；文件不存在返回 0。"""
        try:
            return os.path.getsize(self.db_path)
        except OSError:
            return 0


# ---------------------------------------------------------------- 自检入口

def _check(name: str, cond: bool) -> None:
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        raise AssertionError("self-check failed: " + name)


def _self_test() -> None:
    import shutil

    # 临时目录放在项目根（沙箱/部署环境 %TEMP% 可能不可写；避免 tempfile.mkdtemp，
    # 某些受限环境只允许向常规 mkdir 的目录写文件）
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmpdir = os.path.join(
        _root, "vpsmon_storage_test_%d_%d" % (int(time.time()), os.getpid()))
    os.makedirs(tmpdir, exist_ok=True)

    # ---- 空库行为 -------------------------------------------------------
    db_empty = os.path.join(tmpdir, "empty.db")
    st = Storage(db_empty)
    st.init_db()
    assert st.db_size() >= 0
    _check("WAL 模式生效", st._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal")
    months = st.monthly("eth0")
    _check("空库 monthly 固定 12 项", len(months) == 12)
    _check("空库 monthly 全 0", all(m["rx"] == 0 and m["tx"] == 0 for m in months))
    y, m = _shift_month(datetime.now().year, datetime.now().month, 0)
    ndays = calendar.monthrange(y, m)[1]
    days = st.daily("eth0", "%04d-%02d" % (y, m))
    _check("空库 daily 项数=当月天数", len(days) == ndays)
    _check("空库 daily 全 0", all(d["rx"] == 0 and d["tx"] == 0 for d in days))
    live = st.live("eth0", 30)
    _check("空库 live 速率 0.0", live["rx_rate"] == 0.0 and live["tx_rate"] == 0.0)
    _check("空库 live series 空", live["series"] == [])
    _check("空库 history 空", st.history("eth0", 10) == [])
    _check("空库 latest_sample None", st.latest_sample("eth0") is None)
    _check("空库 recent_samples 空", st.recent_samples("eth0", 10) == [])
    meta = st.status_meta("eth0")
    _check("空库 status_meta", meta["latest_ts"] is None and meta["sample_count"] == 0)
    _check("空库 cpu_mem_history 空", st.cpu_mem_history("eth0", 30) == [])
    _check("空库 list_ifaces_with_counts 空", st.list_ifaces_with_counts() == [])
    for bad in ("bad", "2026-1", "26-01", "202601", "2026-1-2", "2026/01"):
        try:
            st.daily("eth0", bad)
            _check("非法 month %r 抛 ValueError" % bad, False)
        except ValueError:
            _check("非法 month %r 抛 ValueError" % bad, True)
    _check("month 严格 YYYY-MM 合法解析",
           _parse_month("2026-01") == (2026, 1) and _parse_month("0999-12") == (999, 12))
    st.close()

    # ---- 有数据：确定性样例 ---------------------------------------------
    db = os.path.join(tmpdir, "test.db")
    st = Storage(db)
    st.init_db()

    def rec(ts, rx, tx, cpu=1.0, mu=1024, mt=2048, du=4096, dt=8192):
        return dict(ts=ts, iface="eth0", rx_bytes=rx, tx_bytes=tx, cpu=cpu,
                    mem_used=mu, mem_total=mt, disk_used=du, disk_total=dt)

    # 昨天正午锚定（保证同一天、同月、且在过去）：
    #   s0 无前驱→0；s1 Δ+100/+100；s2 rx 回退跳过、tx +100；s3 Δ+200/+50
    from datetime import date, timedelta
    base = int(datetime.combine(date.today() - timedelta(days=1),
                                datetime.min.time().replace(hour=12)).timestamp())
    for i, (rx, tx) in enumerate([(1000, 2000), (1100, 2100), (1050, 2200), (1250, 2250)]):
        st.insert_sample(rec(base - 200 + i * 50, rx, tx))
    ym = datetime.fromtimestamp(base).strftime("%Y-%m")
    d = datetime.fromtimestamp(base).strftime("%Y-%m-%d")
    days = st.daily("eth0", ym)
    by_day = {x["day"]: x for x in days}
    _check("daily 目标日 rx=300", by_day[d]["rx"] == 300)
    _check("daily 目标日 tx=250", by_day[d]["tx"] == 250)
    _check("daily 其余天为 0",
           all(x["rx"] == 0 and x["tx"] == 0 for x in days if x["day"] != d))
    m = {x["month"]: x for x in st.monthly("eth0")}
    _check("monthly 目标月 rx=300", m[ym]["rx"] == 300)
    _check("monthly 目标月 tx=250", m[ym]["tx"] == 250)

    # 当前时刻锚定的 4 条（验证 live/history/最新样本/幂等），间隔 50s：
    #   Δ+100/+100 → 2.0；rx 回退 → 0；Δ+200/+50 → 4.0/1.0
    now = int(time.time())
    for i, (rx, tx) in enumerate([(1000, 2000), (1100, 2100), (1050, 2200), (1250, 2250)]):
        st.insert_sample(rec(now - 150 + i * 50, rx, tx, cpu=10.0 + i))

    _check("insert 幂等：同 (ts,iface) 覆盖", True)
    st.insert_sample(rec(now, 9999, 9999, cpu=42.0))
    st.insert_sample(rec(now, 1250, 2250, cpu=13.0))   # 覆盖回原值
    meta = st.status_meta("eth0")
    _check("status_meta sample_count=8", meta["sample_count"] == 8)
    _check("status_meta latest_ts=now", meta["latest_ts"] == now)

    live = st.live("eth0", 30)
    _check("live 当前 rx_rate=4.0", abs(live["rx_rate"] - 4.0) < 1e-9)
    _check("live 当前 tx_rate=1.0", abs(live["tx_rate"] - 1.0) < 1e-9)
    expect_series = [
        {"ts": now - 150, "rx_rate": 0.0, "tx_rate": 0.0},
        {"ts": now - 100, "rx_rate": 2.0, "tx_rate": 2.0},
        {"ts": now - 50,  "rx_rate": 0.0, "tx_rate": 2.0},   # rx 回退→0
        {"ts": now,       "rx_rate": 4.0, "tx_rate": 1.0},
    ]
    _check("live series 精确匹配", live["series"] == expect_series)

    hist = st.history("eth0", 2)
    _check("history 倒序 2 条", [h["ts"] for h in hist] == [now, now - 50])
    _check("history 最新条速率 4.0/1.0",
           abs(hist[0]["rx_rate"] - 4.0) < 1e-9 and abs(hist[0]["tx_rate"] - 1.0) < 1e-9)
    _check("history 次新条速率 0.0/2.0（rx 回退）",
           hist[1]["rx_rate"] == 0.0 and abs(hist[1]["tx_rate"] - 2.0) < 1e-9)

    ls = st.latest_sample("eth0")
    _check("latest_sample ts=now", ls["ts"] == now and ls["rx_bytes"] == 1250)
    rs = st.recent_samples("eth0", 3)
    _check("recent_samples 倒序 3 条", [r["ts"] for r in rs] == [now, now - 50, now - 100])
    cpus = st.cpu_mem_history("eth0", 30)
    _check("cpu_mem_history 升序且含 cpu 字段",
           [c["ts"] for c in cpus] == [now - 150, now - 100, now - 50, now]
           and all("cpu" in c and "mem_total" in c for c in cpus))
    ifs = st.list_ifaces_with_counts()
    _check("list_ifaces_with_counts 1 网卡",
           len(ifs) == 1 and ifs[0]["iface"] == "eth0" and ifs[0]["count"] == 8)

    # monthly 形状与跨月一致性：daily(当月) 求和 == monthly(当月)
    # （此处重算 monthly，之前取到的 m 是 now 批次入库前的快照）
    m = {x["month"]: x for x in st.monthly("eth0")}
    cur_m = datetime.now().strftime("%Y-%m")
    sum_d = {k: sum(x[k] for x in st.daily("eth0", cur_m)) for k in ("rx", "tx")}
    cur = m[cur_m]
    _check("daily(当月) 求和 == monthly(当月)", sum_d == {"rx": cur["rx"], "tx": cur["tx"]})
    _check("monthly 12 项升序且末项为当月",
           len(months) == 12 and months[-1]["month"] == cur_m
           and months == sorted(months, key=lambda x: x["month"]))
    _check("monthly 当月 rx>=200 tx>=50（确定性上界）",
           cur["rx"] >= 200 and cur["tx"] >= 50)

    st.close()
    shutil.rmtree(tmpdir, ignore_errors=True)
    print("\nAll storage self-checks passed.")


if __name__ == "__main__":
    _self_test()
