# -*- coding: utf-8 -*-
"""vpsmon.collector — 采集线程：psutil 采样 → storage.insert_sample。

对应 SPEC §7 / §8.2 / §8.3：
- 独立 daemon 线程，按 config.interval 秒循环采样；
- 每轮：net_io_counters(pernic=True) → select_iface 确定生效网卡（配置 iface 优先，
  每轮校验候选集，失效自动回退并更新运行态 selected，不重写 config.json）→
  cpu_percent（非阻塞累计式）/ virtual_memory / disk_usage('/') → insert_sample；
- 单轮内任一采集项异常：捕获 + logging，不影响整轮与后续轮次；
- 采样线程是唯一写库者（storage.insert_sample 为 INSERT OR REPLACE，线程安全）；
- cpu_percent 预热：启动后首轮返回无意义值，之后为间隔均值（SPEC §8.2）；
- 速率不做采集期预存：由 storage.live() 基于相邻样本正增量推导（SPEC §8.1/§8.4）。

hostname/boot_time/uptime 不落库（samples 表无对应列，SPEC §5 口径），以运行态
属性暴露，供 api.py /api/status 读取（该端点本就实时读 psutil，见 SPEC §6.2）。

本模块不依赖 Flask；psutil 缺失时自动切换 /proc 采集后端（procmetrics，
OpenWrt 纯标准库路径，SPEC §13.2.1），网卡选择纯函数与自检仍可运行。
自检：python -m vpsmon.collector --self-test
"""

import logging
import os
import socket
import threading
import time
from typing import Dict, Optional

try:
    import psutil
except ImportError:                      # 开发/自检环境可无 psutil；生产由 requirements.txt 保证
    psutil = None                        # type: ignore[assignment]

from vpsmon import procmetrics as procmetrics_mod

log = logging.getLogger("vpsmon.collector")

# SPEC §8.3.2：虚拟网卡名前缀
_VIRT_PREFIXES = ("veth", "docker", "br-", "virbr", "tun", "tap", "vbox", "vmnet")


# ---------------------------------------------------------------- 网卡选择

def select_iface(counters: Dict, prefer: Optional[str] = None) -> Optional[str]:
    """SPEC §8.3 网卡确定性选择（纯函数，便于假数据自检）。

    counters: psutil.net_io_counters(pernic=True) 的 dict {name: io}。
    prefer:   config.iface（空串/None = 自动选择）；非空且为有效候选时优先，
              否则自动回退（SPEC §8.3.5：每轮校验，失效自动回退）。
    返回选中网卡名；counters 为空返回 None。
    """
    if not counters:
        return None

    def total(name):
        io = counters[name]
        # SPEC §13.2.1：归一化两种计数视图（psutil 属性 / procmetrics dict）
        return (procmetrics_mod.io_bytes(io, "bytes_recv", "rx_bytes")
                + procmetrics_mod.io_bytes(io, "bytes_sent", "tx_bytes"))

    def valid(name):
        return (name != "lo"
                and not name.startswith(_VIRT_PREFIXES)
                and total(name) > 0)

    candidates = [n for n in counters if valid(n)]
    if not candidates:                   # §8.3.3 放宽：所有非回环网卡取累计最大
        candidates = [n for n in counters if n != "lo"]
    if not candidates:
        return None
    # 确定性：累计字节最大，并列取名字典序最大（SPEC §8.3.4）
    chosen = max(candidates, key=lambda n: (total(n), n))
    if prefer and prefer in candidates:
        return prefer
    return chosen


# ---------------------------------------------------------------- 采集线程

class Collector:
    """采样线程。start() 启动 daemon 线程，stop() 用 threading.Event 优雅停止。"""

    def __init__(self, storage, config):
        self.storage = storage
        self.cfg = dict(config or {})
        self.interval = int(self.cfg.get("interval") or 60)
        if self.interval < 1:
            self.interval = 60           # 区间校验由 config.py 负责（下限 5），此处仅防御
        self._prefer = (self.cfg.get("iface") or "").strip() or None
        self._stop = threading.Event()
        self._thread = None
        # ---- 运行态（api.py 可读取） ----
        self.selected = None             # 当前生效统计网卡
        self.hostname = ""
        self.boot_time = None            # 系统开机 Unix 秒
        self.uptime = None               # 系统开机秒数（每轮刷新）
        # ---- 上一轮成功采集的可选指标（单点失败时回退用） ----
        self._prev_cpu = 0.0
        self._prev_mem = (0, 0)
        self._prev_disk = (0, 0)

    # ------------------------------------------------------ 生命周期

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="vpsmon-collector", daemon=True)
        self._thread.start()
        log.info("collector started: interval=%ss iface=%s",
                 self.interval, self._prefer or "(auto)")

    def stop(self, timeout: Optional[float] = None) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout if timeout is not None else self.interval + 5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample_once()
            except Exception:            # 顶层兜底：任何未预期异常不中断采集线程
                log.exception("collector round failed")
            self._stop.wait(self.interval)

    # ------------------------------------------------------ 单轮采样

    def sample_once(self) -> None:
        """执行一轮采样并写库。核心项（网卡计数）失败则整轮放弃；可选指标单点
        失败记录日志并回退到上一轮值，不影响本轮与后续轮次。

        采集后端（SPEC §13.2.1）：psutil 可用 → psutil；否则自动走 /proc
        （procmetrics，OpenWrt 路径）。两后端返回同形状数据。"""
        backend = procmetrics_mod.metrics_backend(psutil_mod=psutil)
        if backend is None:
            log.error("无可用采集后端（psutil 与 /proc 均不可用）")
            return
        # 1) 网卡累计计数（核心，失败则整轮放弃）
        try:
            counters = backend.net_counters()
        except Exception:
            log.exception("net_io_counters 失败，跳过本轮")
            return
        iface = select_iface(counters, self._prefer)
        if iface is None:
            log.warning("无可用网卡（候选集为空），跳过本轮")
            return
        if iface != self.selected:
            if self.selected is not None:
                log.warning("统计网卡变更: %s -> %s（配置网卡失效自动回退）",
                            self.selected, iface)
            else:
                log.info("选定统计网卡: %s", iface)
            self.selected = iface
        io = counters[iface]
        rx_bytes = procmetrics_mod.io_bytes(io, "bytes_recv", "rx_bytes")
        tx_bytes = procmetrics_mod.io_bytes(io, "bytes_sent", "tx_bytes")

        # 2) 可选指标（单点失败 → 记录 + 回退上一轮值）
        def _mem_pair():
            m = backend.meminfo()
            return (int(m["used"]), int(m["total"]))

        def _disk_pair():
            d = backend.disk_usage("/")
            return (int(d["used"]), int(d["total"]))

        cpu = self._safe_metric("cpu_percent",
                                lambda: backend.cpu_percent(),
                                self._prev_cpu)
        self._prev_cpu = cpu
        mem = self._safe_metric("virtual_memory", _mem_pair, self._prev_mem)
        self._prev_mem = mem
        disk = self._safe_metric("disk_usage", _disk_pair, self._prev_disk)
        self._prev_disk = disk
        boot = self._safe_metric("boot_time", lambda: backend.boot_time(),
                                 self.boot_time)
        if boot is not None:
            self.boot_time = boot
            self.uptime = max(0, int(time.time() - boot))
        try:
            self.hostname = socket.gethostname()
        except Exception:
            pass                          # hostname 失败非关键，不打扰日志

        # 3) 写库（采样线程是唯一写库者；ts = int(time.time())，SPEC §8.5）
        self.storage.insert_sample({
            "ts": int(time.time()),
            "iface": iface,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "cpu": cpu,
            "mem_used": mem[0],
            "mem_total": mem[1],
            "disk_used": disk[0],
            "disk_total": disk[1],
        })

    @staticmethod
    def _safe_metric(name, fn, prev):
        try:
            return fn()
        except Exception:
            log.warning("采集项 %s 失败，回退到上一轮值", name, exc_info=True)
            return prev


# ---------------------------------------------------------------- 自检

def _self_test() -> None:
    import shutil
    from types import SimpleNamespace as NS

    ok = []
    def check(name, cond):
        ok.append(cond)
        print(("PASS  " if cond else "FAIL  ") + name)

    # ---- 1) select_iface 纯函数（假数据） ----
    def io(rx, tx):
        return NS(bytes_recv=rx, bytes_sent=tx)

    counters = {
        "lo": io(10 ** 9, 10 ** 9),
        "eth0": io(10 ** 10, 5 * 10 ** 9),
        "docker0": io(10 ** 8, 10 ** 8),
        "veth_ab": io(10 ** 7, 10 ** 7),
        "ens3": io(2 * 10 ** 10, 10 ** 10),
    }
    check("自动选择：累计字节最大 ens3", select_iface(counters) == "ens3")
    check("配置优先：prefer=eth0 → eth0", select_iface(counters, "eth0") == "eth0")
    check("配置失效：prefer=docker0(虚拟) → 自动 ens3",
          select_iface(counters, "docker0") == "ens3")
    check("配置失效：prefer=lo(回环) → 自动 ens3",
          select_iface(counters, "lo") == "ens3")
    c2 = {"lo": io(1, 1), "docker0": io(100, 100), "veth_x": io(50, 50)}
    check("全虚拟：放宽取累计最大 docker0", select_iface(c2) == "docker0")
    c3 = {"lo": io(0, 0), "eth0": io(0, 0), "ens3": io(0, 0)}
    check("全零：放宽取非回环最大（并列名字典序）eth0", select_iface(c3) == "eth0")
    check("空计数器 → None", select_iface({}) is None)

    # ---- 2) 采样写库（注入假 psutil） ----
    # 注意：python -m 运行时本模块名为 __main__，import 自身会得到第二个实例，
    # 必须通过 sys.modules[__name__] 取当前模块再注入。
    import sys
    import vpsmon.storage as storage
    col = sys.modules[__name__]
    real_psutil = col.psutil
    fake = _FakePsutil()
    col.psutil = fake

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmpdir = os.path.join(root, "vpsmon_collector_test_%d_%d"
                          % (int(time.time()), os.getpid()))
    os.makedirs(tmpdir, exist_ok=True)
    st = st2 = None
    try:
        # 2a) 自动选择 + 采样写库
        st = storage.Storage(os.path.join(tmpdir, "a.db"))
        st.init_db()
        ca = Collector(st, {"interval": 1, "iface": ""})
        ca.start()
        time.sleep(2.4)
        ca.stop()
        check("采样线程存活后正常停止", ca._thread is not None)
        check("自动选择生效网卡 eth0", ca.selected == "eth0")
        meta = st.status_meta("eth0")
        check("至少采样 2 轮", meta["sample_count"] >= 2)
        ls = st.latest_sample("eth0")
        check("样本计数正确 rx=1e10 tx=5e9",
              ls["rx_bytes"] == 10 ** 10 and ls["tx_bytes"] == 5 * 10 ** 9)
        check("样本 cpu=12.5", ls["cpu"] == 12.5)
        check("样本 mem_total=8GiB disk_total=100GiB",
              ls["mem_total"] == 8 * 2 ** 30 and ls["disk_total"] == 100 * 2 ** 30)
        check("uptime ≈ 7200s", ca.uptime is not None and abs(ca.uptime - 7200) <= 2)
        check("hostname 非空", isinstance(ca.hostname, str) and len(ca.hostname) > 0)

        # 2b) 配置 iface 优先 + 失效自动回退 + 单点异常隔离
        st2 = storage.Storage(os.path.join(tmpdir, "b.db"))
        st2.init_db()
        cb = Collector(st2, {"interval": 1, "iface": "eth0"})
        cb.start()
        time.sleep(1.3)
        check("配置优先：selected=eth0", cb.selected == "eth0")
        # eth0 消失 → 下一轮自动回退
        fake.counters = {"lo": io(1, 1), "ens9": io(5 * 10 ** 9, 2 * 10 ** 9)}
        time.sleep(1.3)
        check("配置网卡失效自动回退 ens9", cb.selected == "ens9")
        # disk_usage 单点失败 → 本轮仍写库，disk 回退上一轮值
        prev_disk = st2.latest_sample("ens9")
        fake.fail_disk = True
        time.sleep(1.3)
        cur = st2.latest_sample("ens9")
        fake.fail_disk = False
        check("disk 失败后本轮仍写库", cur is not None and cur["ts"] > prev_disk["ts"])
        check("disk 失败回退上一轮值",
              cur["disk_used"] == prev_disk["disk_used"]
              and cur["disk_total"] == prev_disk["disk_total"])
        cb.stop()
        check("stop() 后线程停止", not cb._thread.is_alive())
    finally:
        col.psutil = real_psutil
        if st is not None:
            st.close()
        if st2 is not None:
            st2.close()
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\ncollector self-test: %d/%d passed" % (sum(ok), len(ok)))
    if not all(ok):
        raise SystemExit("self-test FAILED")


class _FakePsutil:
    """假 psutil：确定性数据，支持单点故障注入（fail_disk）。"""

    def __init__(self):
        self.counters = {
            "lo": self._io(10 ** 9, 10 ** 9),
            "eth0": self._io(10 ** 10, 5 * 10 ** 9),
            "docker0": self._io(10 ** 8, 10 ** 8),
        }
        self.fail_disk = False

    @staticmethod
    def _io(rx, tx):
        from types import SimpleNamespace as NS
        return NS(bytes_recv=rx, bytes_sent=tx)

    def net_io_counters(self, pernic=False):
        if pernic:
            return self.counters
        rx = sum(int(v.bytes_recv) for v in self.counters.values())
        tx = sum(int(v.bytes_sent) for v in self.counters.values())
        return self._io(rx, tx)

    def cpu_percent(self, interval=None):
        return 12.5

    def virtual_memory(self):
        from types import SimpleNamespace as NS
        return NS(used=3 * 2 ** 30, total=8 * 2 ** 30)

    def disk_usage(self, path):
        from types import SimpleNamespace as NS
        if self.fail_disk:
            raise OSError("fake disk_usage failure")
        return NS(used=20 * 2 ** 30, total=100 * 2 ** 30)

    def boot_time(self):
        return time.time() - 7200


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        _self_test()
    else:
        print("用法: python -m vpsmon.collector --self-test")
        print("说明: 自检使用假 psutil 数据，无需安装 psutil 即可运行。")
