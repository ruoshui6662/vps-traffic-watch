# -*- coding: utf-8 -*-
"""vpsmon.procmetrics — OpenWrt 纯标准库采集后端（/proc 读取，无 psutil/无 C 扩展）。

SPEC §13.2.1：psutil 缺失/采集失败时，collector.py 与 api.py 通过
`metrics_backend()` 自动切换到此后端。每个函数返回与 psutil 调用**相同形状**的数据：

    net_dev()      {iface: {"rx_bytes": int, "tx_bytes": int}}   ← net_io_counters(pernic=True)
    cpu_percent()  float（增量，首次 0.0，clamp [0,100]）          ← cpu_percent(interval=None)
    meminfo()      {"used": int, "total": int}                   ← virtual_memory()
    disk_usage(p)  {"used": int, "total": int}                   ← disk_usage(path)
    uptime_sec()   int                                            ← /proc/uptime 首字段
    boot_time()    int                                            ← now - uptime 推导

设计要点：

- `ProcMetrics(proc_dir="/proc")`：proc_dir 可注入（测试用假 /proc 目录树）；
- `PsutilBackend(psutil_mod)`：psutil 的同形状适配器（collector 的假 psutil 注入
  也走此适配器，自检零改动）；
- `metrics_backend(psutil_mod=None)`：psutil 可用 → PsutilBackend；否则 → 共享
  ProcMetrics 单例（CPU 基线跨调用者共享，语义与 psutil 全局计数器一致）；
- `io_bytes(io, attr, key)`：归一化两种网卡计数视图——psutil 对象的
  `.bytes_recv/.bytes_sent` 属性与 procmetrics 的 {"rx_bytes","tx_bytes"} dict，
  供 select_iface / api 读取（SPEC §13.2.1 约束）；
- 任一 /proc 文件读取异常 → 抛异常，由调用方（collector 单点失败回退 / api
  status 回退库内样本）按既有语义处理，不中断整轮；
- net_dev 保留 lo 与虚拟网卡（形状与 psutil pernic=True 一致），过滤由
  select_iface / interfaces 端点在业务层完成。

本模块仅依赖 stdlib，import 期不触碰 flask/psutil（OpenWrt 缺包安全）。
自检：python -m vpsmon.procmetrics --self-test（假 /proc 文件注入，无需 psutil）
"""

import os
import socket
import time


def io_bytes(io, psutil_attr, dict_key):
    """归一化网卡计数读取（SPEC §13.2.1）：优先 psutil 属性视图，其次 dict 视图。

    io: psutil 对象（含 .bytes_recv/.bytes_sent）或 dict（含 rx_bytes/tx_bytes）。
    返回 int；两视图均缺失 → 0（空值防御）。
    """
    v = getattr(io, psutil_attr, None)
    if v is None:
        if isinstance(io, dict):
            return int(io.get(dict_key, 0))
        return 0
    return int(v)


def _read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


class ProcMetrics:
    """/proc 采集后端。proc_dir 默认 "/proc"，测试可注入假目录树（net/dev、stat、
    meminfo、uptime 等相对路径）。"""

    def __init__(self, proc_dir="/proc"):
        self.proc_dir = proc_dir
        self._cpu_prev = None            # (total, idle, wall) 上次基线

    def _read(self, rel_path):
        return _read_text(os.path.join(self.proc_dir, rel_path))

    # ------------------------------------------------------------ 网卡

    def net_dev(self, path=None):
        """/proc/net/dev → {iface: {"rx_bytes", "tx_bytes"}}（含 lo，形状同 pernic=True）。

        跳过第 1–2 行表头；每行按 ':' 取网卡名，右侧字段按空白拆分：
        字段 0 = rx_bytes、字段 8 = tx_bytes；字段缺失/非数字防御为 0。
        """
        text = self._read(os.path.join("net", "dev")) if path is None \
            else _read_text(path)
        out = {}
        for i, line in enumerate(text.splitlines()):
            if i < 2:                    # 表头两行
                continue
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            name = name.strip()
            if not name:
                continue
            fields = rest.split()

            def _val(idx):
                try:
                    return int(fields[idx])
                except (IndexError, ValueError):
                    return 0
            out[name] = {"rx_bytes": _val(0), "tx_bytes": _val(8)}
        return out

    def net_counters(self):
        """与 psutil.net_io_counters(pernic=True) 同形状的别名。"""
        return self.net_dev()

    # ------------------------------------------------------------ CPU

    def cpu_percent(self, stat_path=None):
        """非阻塞 CPU 增量（/proc/stat 首行，interval=None 语义）。

        total = 全部字段和，idle = idle + iowait；
        首次调用记录基线并返回 0.0（与 psutil 首调语义一致）；
        之后 pct = (1 - Δidle/Δtotal) * 100，clamp 到 [0, 100]；
        计数器重置（Δtotal <= 0）→ 重新基线并返回 0.0。
        """
        text = self._read("stat") if stat_path is None else _read_text(stat_path)
        lines = text.splitlines()
        parts = lines[0].split() if lines else []
        nums = []
        for p in parts[1:]:
            try:
                nums.append(int(p))
            except ValueError:
                nums.append(0)
        total = sum(nums)
        idle = (nums[3] if len(nums) > 3 else 0) + (nums[4] if len(nums) > 4 else 0)
        now = time.monotonic()
        prev = self._cpu_prev
        self._cpu_prev = (total, idle, now)
        if prev is None or total - prev[0] <= 0:
            return 0.0
        dt_total = total - prev[0]
        dt_idle = idle - prev[1]
        pct = (1.0 - dt_idle / dt_total) * 100.0
        return min(100.0, max(0.0, pct))

    # ------------------------------------------------------------ 内存

    def meminfo(self, path=None):
        """/proc/meminfo → {"used", "total"}（kB → 字节）。

        total = MemTotal；used = MemTotal - MemAvailable（内核 3.14+）；
        无 MemAvailable（老内核）回退 MemTotal - (MemFree + Buffers + Cached
        + SReclaimable)。
        """
        text = self._read("meminfo") if path is None else _read_text(path)
        vals = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, rest = line.split(":", 1)
            parts = rest.split()
            try:
                v = int(parts[0])
            except (IndexError, ValueError):
                continue
            if len(parts) > 1 and parts[1].strip().lower() in ("kb", "kib"):
                v *= 1024
            vals[key.strip()] = v
        total = vals.get("MemTotal", 0)
        avail = vals.get("MemAvailable")
        if avail is not None:
            used = total - avail
        else:
            used = total - (vals.get("MemFree", 0) + vals.get("Buffers", 0)
                            + vals.get("Cached", 0) + vals.get("SReclaimable", 0))
        return {"used": max(0, used), "total": total}

    # ------------------------------------------------------------ 磁盘

    def disk_usage(self, path="/"):
        """os.statvfs(path) → {"used", "total"}（与 psutil.disk_usage 口径一致）。

        OpenWrt/Linux 走 statvfs；Windows 无 os.statvfs 时回退 shutil.disk_usage
        （开发机调试用，口径一致：total=f_blocks*f_frsize，used 同理）。
        """
        if hasattr(os, "statvfs"):
            st = os.statvfs(path)
            frsize = st.f_frsize
            total = st.f_blocks * frsize
            used = (st.f_blocks - st.f_bfree) * frsize
            return {"used": used, "total": total}
        import shutil
        du = shutil.disk_usage(path)
        return {"used": du.used, "total": du.total}

    # ------------------------------------------------------------ 系统

    def uptime_sec(self, path=None):
        """/proc/uptime 首字段 → int 秒。"""
        text = self._read("uptime") if path is None else _read_text(path)
        try:
            return int(float(text.split()[0]))
        except (IndexError, ValueError):
            return 0

    def boot_time(self):
        """开机时间（Unix 秒）：now - uptime。"""
        return int(time.time()) - self.uptime_sec()

    def uptime(self):
        return self.uptime_sec()

    def hostname(self):
        try:
            return socket.gethostname()
        except Exception:
            return ""


class PsutilBackend:
    """psutil 的同形状适配器：与 ProcMetrics 同名方法、同形状返回。

    collector/api 共用；也承担假 psutil 注入（自检）。"""

    def __init__(self, psutil_mod):
        self._p = psutil_mod

    def net_counters(self):
        return self._p.net_io_counters(pernic=True)

    def cpu_percent(self):
        return self._p.cpu_percent(interval=None)

    def meminfo(self):
        vm = self._p.virtual_memory()
        return {"used": vm.used, "total": vm.total}

    def disk_usage(self, path):
        du = self._p.disk_usage(path)
        return {"used": du.used, "total": du.total}

    def boot_time(self):
        return self._p.boot_time()

    def uptime(self):
        return max(0, int(time.time() - self._p.boot_time()))

    def hostname(self):
        try:
            return socket.gethostname()
        except Exception:
            return ""


_proc_default = None


def metrics_backend(psutil_mod=None):
    """采集后端选择（SPEC §13.2.1）：psutil 可用 → PsutilBackend；否则 → 共享 /proc。

    psutil_mod: 调用方持有的 psutil 引用（collector/api 各自的模块全局，
    自检时可注入假实现）；None → 用默认 ProcMetrics 单例（/proc）。
    """
    if psutil_mod is not None:
        return PsutilBackend(psutil_mod)
    global _proc_default
    if _proc_default is None:
        _proc_default = ProcMetrics()
    return _proc_default


# ---------------------------------------------------------------- 自检

def _self_test() -> None:
    """假 /proc 文件注入自检：多网卡、CPU 多行/增量/重置、meminfo 变体、形状。"""
    import shutil
    from types import SimpleNamespace as NS

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmpdir = os.path.join(root, "vpsmon_proc_test_%d_%d"
                          % (int(time.time()), os.getpid()))
    os.makedirs(tmpdir, exist_ok=True)
    os.makedirs(os.path.join(tmpdir, "net"), exist_ok=True)
    ok = []

    def check(name, cond):
        ok.append(cond)
        print(("PASS  " if cond else "FAIL  ") + name)

    def write(rel, text):
        p = os.path.join(tmpdir, rel)
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)

    try:
        # ---- 1) net/dev：多网卡 + 表头两行 + 空值防御 ----
        write("net/dev", (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            "    lo: 1000    10 0 0 0 0 0 0      1000    10 0 0 0 0 0 0\n"
            "  eth0: 500000  5 0 0 0 0 0 0       700000  7 0 0 0 0 0 0\n"
            "docker0: 300 3 0 0 0 0 0 0          400 4 0 0 0 0 0 0\n"
            "  br-lan: 0 0 0 0 0 0 0 0           0 0 0 0 0 0 0 0\n"
        ))
        pm = ProcMetrics(proc_dir=tmpdir)
        nd = pm.net_dev()
        check("net_dev 含 4 网卡（含 lo，形状同 psutil pernic）",
              set(nd) == {"lo", "eth0", "docker0", "br-lan"})
        check("net_dev 字段0=rx 字段8=tx（eth0=500000/700000）",
              nd["eth0"]["rx_bytes"] == 500000 and nd["eth0"]["tx_bytes"] == 700000)
        check("net_dev 空值防御为 0（br-lan 全 0）",
              nd["br-lan"]["rx_bytes"] == 0 and nd["br-lan"]["tx_bytes"] == 0)
        check("net_dev 保留 lo（业务层才过滤）", nd["lo"]["rx_bytes"] == 1000)
        check("net_dev 形状可被 io_bytes 归一化读取",
              io_bytes(nd["eth0"], "bytes_recv", "rx_bytes") == 500000)

        # ---- 2) io_bytes 归一化：属性形状 与 dict 形状 ----
        check("io_bytes NS 属性形状",
              io_bytes(NS(bytes_recv=5, bytes_sent=7), "bytes_recv", "rx_bytes") == 5
              and io_bytes(NS(bytes_recv=5, bytes_sent=7), "bytes_sent", "tx_bytes") == 7)
        check("io_bytes dict 形状",
              io_bytes({"rx_bytes": 5, "tx_bytes": 7}, "bytes_recv", "rx_bytes") == 5
              and io_bytes({"rx_bytes": 5, "tx_bytes": 7}, "bytes_sent", "tx_bytes") == 7)
        check("io_bytes 属性为 0 不误落 dict 分支",
              io_bytes(NS(bytes_recv=0, bytes_sent=0), "bytes_recv", "rx_bytes") == 0)

        # ---- 3) CPU 增量：首调 0.0 → 100% → 0% → 50% → 重置 0.0（多行 stat）----
        write("stat", "cpu  0 0 0 0 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0 0\n")
        pm2 = ProcMetrics(proc_dir=tmpdir)
        check("cpu 首调 0.0（记录基线）", pm2.cpu_percent() == 0.0)
        write("stat", "cpu  100 0 0 0 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0 0\n")
        check("cpu 100%（Δtotal=100 Δidle=0）", abs(pm2.cpu_percent() - 100.0) < 1e-9)
        write("stat", "cpu  100 0 0 100 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0 0\n")
        check("cpu 0%（Δtotal=100 Δidle=100）", abs(pm2.cpu_percent()) < 1e-9)
        write("stat", "cpu  150 0 0 150 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0 0\n")
        check("cpu 50%（Δtotal=100 Δidle=50）", abs(pm2.cpu_percent() - 50.0) < 1e-9)
        write("stat", "cpu  100 0 0 100 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0 0\n")
        check("cpu 计数器重置（Δtotal<=0）→ 0.0 且重新基线",
              pm2.cpu_percent() == 0.0)

        # ---- 4) meminfo：MemAvailable 变体 + 老内核回退 ----
        write("meminfo", (
            "MemTotal:        1000 kB\nMemFree:          100 kB\nMemAvailable:     400 kB\n"
            "Buffers:          50 kB\nCached:           300 kB\nSReclaimable:      50 kB\n"
        ))
        m = pm.meminfo()
        check("meminfo total=1024000（kB→字节）", m["total"] == 1000 * 1024)
        check("meminfo used=MemTotal-MemAvailable=614400", m["used"] == 614400)
        write("meminfo", (
            "MemTotal:        1000 kB\nMemFree:          100 kB\n"
            "Buffers:          50 kB\nCached:           300 kB\nSReclaimable:      50 kB\n"
        ))
        m2 = pm.meminfo()
        check("老内核回退 used=total-(Free+Buffers+Cached+SRec)=512000",
              m2["used"] == 500 * 1024)

        # ---- 5) uptime / boot_time ----
        write("uptime", "1234.56 789.01\n")
        check("uptime_sec=1234", pm.uptime_sec() == 1234)
        check("boot_time ≈ now-1234", abs((int(time.time()) - pm.boot_time()) - 1234) <= 1)

        # ---- 6) disk_usage（真实调用，仅验形状；Windows 走 shutil 回退） ----
        d = pm.disk_usage(tmpdir)
        check("disk_usage 形状 used/total 整数且 total>0",
              isinstance(d["used"], int) and isinstance(d["total"], int)
              and d["total"] > 0 and 0 <= d["used"] <= d["total"])

        # ---- 7) hostname ----
        check("hostname 非空", isinstance(pm.hostname(), str) and len(pm.hostname()) > 0)

        # ---- 8) metrics_backend 选择：psutil 适配器 / /proc 单例 ----
        class FakeP:
            def net_io_counters(self, pernic=False):
                return {}

            def cpu_percent(self, interval=None):
                return 1.0

            def virtual_memory(self):
                return NS(used=1, total=2)

            def disk_usage(self, path):
                return NS(used=3, total=4)

            def boot_time(self):
                return 5

        b = metrics_backend(psutil_mod=FakeP())
        check("metrics_backend(psutil) → PsutilBackend 同形状",
              b.cpu_percent() == 1.0 and b.meminfo() == {"used": 1, "total": 2}
              and b.disk_usage("/") == {"used": 3, "total": 4}
              and b.boot_time() == 5 and b.uptime() >= 0)
        b2 = metrics_backend()
        check("metrics_backend() 无 psutil → ProcMetrics 单例",
              isinstance(b2, ProcMetrics) and metrics_backend() is b2)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\nprocmetrics self-test: %d/%d passed" % (sum(ok), len(ok)))
    if not all(ok):
        raise SystemExit("procmetrics self-test FAILED")


if __name__ == "__main__":
    import sys
    if "--self-test" in sys.argv:
        _self_test()
    else:
        print("用法: python -m vpsmon.procmetrics --self-test")
        print("说明: 使用假 /proc 目录树注入，无需 psutil 即可运行。")
