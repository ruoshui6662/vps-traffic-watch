# VPS 流量统计监控系统 — 技术规格说明（SPEC）

- 版本：1.1（t3 新增 §13"OpenWrt 支持"；1.0 为 t1 架构评审与规格定义）
- 作者：researcher（架构师）
- 状态：已评审，可作为后端/前端/运维的直接实现依据；§13 为 T4（标准库运行时）/ T5（安装分支）的实现依据
- 目标平台：Linux VPS（Debian/Ubuntu/CentOS/Alpine 系）；OpenWrt 路由器（opkg/procd/uci，见 §13）；开发环境 Windows（Python3 可直接运行调试）

---

## 1. 概述

单机部署的轻量监控服务：每 `interval` 秒采集一次所选网卡的**内核累计收发字节数**、CPU 使用率、内存与磁盘占用，写入 SQLite；通过 Web 服务（VPS 用 Flask，OpenWrt 用纯标准库 `http.server`，§13.2）提供 JSON API 与一个 ECharts 仪表盘页面，浏览器访问 `http://<IP>:<port>` 查看月度/日度流量、实时速率与系统状态。

设计原则：

- **只存累计计数，不存速率**：样本表存内核单调计数（rx_bytes/tx_bytes），速率与月度/日度流量全部由查询时基于相邻样本**正增量**推导，天然免疫计数器重置与进程重启。
- **单写多读**：采集线程单写入者，Flask API 只读；SQLite WAL 模式下无写锁争用。
- **零外部依赖的部署形态**：VPS 仅 Flask/psutil 两个依赖；OpenWrt 分支零依赖（纯标准库，§13.2）；前端静态文件本地托管（ECharts 本地 vendor，避免 VPS 无外网时 UI 白屏）。

---

## 2. 技术栈与版本要求

| 组件 | 版本 | 说明 |
|---|---|---|
| Python | >= 3.8 | 开发与部署一致 |
| Flask | >= 3.0, < 4.0 | Web 框架（自带开发服务器，单用户监控足够） |
| psutil | >= 5.9 | 网卡/CPU/内存/磁盘采集 |
| SQLite | 随 Python 内置（stdlib sqlite3） | 需支持 WAL（3.7+，全平台满足） |
| ECharts | 5.x | 前端图表库，`static/vendor/echarts.min.js` 本地放置 |

requirements.txt 内容（交付物）：

```
flask>=3.0,<4
psutil>=5.9
```

> 取舍说明：生产不引入 gunicorn/waitress——单用户自监控场景 Flask 内置服务器足够；若未来并发升高，可在不改变 API 的前提下替换 WSGI 服务器（见 §10）。
>
> **OpenWrt 平台降级形态（§13.2）**：OpenWrt 分支**不部署 Flask/psutil**（无 pip/venv 惯例、无 gcc，无法编译 C 扩展）。运行时自动降级为**纯标准库后端**：采集改用 `/proc` 读取（`procmetrics.py`），Web 改用 `http.server.ThreadingHTTPServer`（`stdserver.py`）；API 契约（§6 六端点）与安全基线（SECURITY.md §4 全部条目）与 Flask 版**逐字段一致**。

---

## 3. 目录布局（最终交付物）

```
D:\AI编程\vps流量统计\              （项目根目录 = 开发工作目录）
├── install.sh                      # 一键安装脚本（Linux 部署；支持 uninstall 子命令）
├── uninstall.sh                    # 卸载脚本（install.sh uninstall 的内部实现，也可独立执行）
├── requirements.txt                # Python 依赖
├── README.md                       # 安装/使用/API 说明（reviewer 交付）
├── vpsmon.service                  # systemd 单元文件模板（install.sh 使用）
├── docs\
│   └── SPEC.md                     # 本文档
├── .gitignore                      # 忽略 *.db、__pycache__、venv、config.json
└── vpsmon\                         # Python 包
    ├── __init__.py                 # 空文件，声明包
    ├── app.py                      # 入口：加载配置→初始化存储→启动采集线程→选择后端（Flask / stdlib，§13.2）
    ├── config.py                   # 配置加载/校验/默认值回退（探测路径含 /etc/vpsmon，§13.3）
    ├── collector.py                # 采集线程：psutil 或 /proc 采样→写库；网卡自动选择（§13.2）
    ├── storage.py                  # SQLite：建表/WAL/写样本/聚合查询（正增量算法在此）
    ├── api.py                      # API 处理器（纯函数）+ Flask Blueprint 薄适配层；6 端点 + token 鉴权
    ├── security.py                 # 框架无关安全原语：鉴权/限流/白名单/安全头/Host 校验（§13.2.2，双后端复用）
    ├── procmetrics.py              # /proc 采集后端：net_dev/cpu/meminfo/statvfs/uptime（psutil 缺失时启用）
    ├── stdserver.py                # 纯标准库 HTTP 服务器：ThreadingHTTPServer + 路由/安全门/静态文件（§13.2.3）
    └── static\
        ├── index.html              # 仪表盘单页
        ├── css\style.css           # 样式
        ├── js\app.js               # ECharts 渲染 + API 调用 + token 管理
        └── vendor\echarts.min.js   # ECharts 5.x 本地文件（frontend 交付时放置）
```

**部署态目录（install.sh 产出）**：

```
/opt/vpsmon/                 # 程序（vpsmon 包 + requirements.txt + venv/）
/opt/vpsmon/venv/            # 虚拟环境
/var/lib/vpsmon/             # 数据目录（属主 vpsmon:vpsmon，权限 700）
/var/lib/vpsmon/config.json  # 配置（权限 600，含 token 不对外可读）
/var/lib/vpsmon/vpsmon.db    # SQLite 数据库（WAL 模式的 -wal/-shm 同目录）
/etc/systemd/system/vpsmon.service
```

**OpenWrt 部署态（§13.3，install.sh OpenWrt 分支产出）**：

```
/opt/vpsmon/                 # 程序（vpsmon 包；无 venv/pip，无编译物）
/etc/vpsmon/                 # 数据/配置目录（overlay 持久，权限 700）
/etc/vpsmon/config.json      # 配置（600，含 token）
/etc/vpsmon/vpsmon.db        # SQLite（WAL 模式；db 由 config 同目录推导）
/etc/init.d/vpsmon           # procd init 脚本（START=99 STOP=10）
/etc/rc.d/S99vpsmon          # enable 生成的开机启动链接
/etc/config/firewall         # uci 防火墙规则（name=vpsmon 的 ACCEPT 段）
```

**路径推导规则（重要，前后端/运维共用）**：`app.py` 接受 `--config <path>`；**数据库文件默认位于配置文件所在目录下的 `vpsmon.db`**（开发模式 `./config.json` → `./vpsmon.db`；部署模式 `/var/lib/vpsmon/config.json` → `/var/lib/vpsmon/vpsmon.db`）。`--db <path>` 可显式覆盖（供测试/卸载脚本用）。数据目录不存在时自动创建（`os.makedirs`）。

---

## 4. 配置 config.json

### 4.1 格式与默认值

```json
{
  "port": 8080,
  "interval": 60,
  "token": "",
  "iface": "",
  "bind": "0.0.0.0",
  "allow_ips": [],
  "rate_limit": 60,
  "allow_url_token": false,
  "ssl_certfile": "",
  "ssl_keyfile": "",
  "trusted_proxy": "",
  "debug": false
}
```

| 字段 | 类型 | 默认 | 约束与行为 |
|---|---|---|---|
| `port` | int | 8080 | 监听端口。非 1–65535 整数 → 回退 8080 并打日志（安装脚本不静默默认，见 §9） |
| `interval` | int | 60 | 采集间隔（秒）。下限 5（防写库过频），非 5–86400 → 回退 60 |
| `token` | string | `""` | 鉴权令牌。空 = 关闭鉴权；非空 = 开启（见 §6.1）。一键安装默认**自动生成强随机 128bit**（SECURITY §4.10-B） |
| `iface` | string | `""` | 统计网卡名。空 = 启动时自动选择（见 §8.3） |
| `db_path` | string | （可选） | 显式指定数据库路径，覆盖 §3 推导规则 |
| `keep_days` | int | 0 | （可选扩展）保留样本天数，0=无限；>0 时每日清理 |
| `bind` | string | `"0.0.0.0"` | 监听地址（SECURITY §4.4）。设 `127.0.0.1` 仅本机可访问（配反代或本机使用） |
| `allow_ips` | array | `[]` | IP 白名单（SECURITY §4.3）：`1.2.3.4` / `10.0.0.0/8` / `2001:db8::/32`，也接受逗号分隔字符串；非法条目丢弃。空 = 不限制；非空时未命中 → `403` |
| `rate_limit` | int | 60 | 限流（次/分钟/IP，SECURITY §4.2）；`0` = 关闭；超限 → `429` |
| `allow_url_token` | bool | `false` | 是否允许 `?token=` 查询参数鉴权（SECURITY §4.1）。默认 `false` 仅认 `X-Token` 头；`true` 恢复旧兼容行为（有日志泄露风险） |
| `ssl_certfile` / `ssl_keyfile` | string | `""` | TLS 证书/密钥（SECURITY §4.5）。必须成对配置且文件存在才启用 HTTPS；缺一半回退关闭；配置但文件缺失 → 拒绝以明文启动 |
| `trusted_proxy` | string | `""` | 信任的反代地址（SECURITY §4.2）。仅来自该地址的请求才采信 `X-Forwarded-For` 首段（用于限流/白名单的真实客户端 IP） |
| `debug` | bool | `false` | 调试开关。**即使配置 `true` 也强制回退 `false`**（生产禁止调试器，SECURITY §4.8.1） |

### 4.2 加载顺序（config.py 实现）

1. 环境变量 `VPSMON_CONFIG` 指向的路径；
2. `app.py --config <path>` 参数（优先级最高，覆盖环境变量）；
3. 未指定 → 按顺序探测：`/var/lib/vpsmon/config.json` → 当前工作目录 `./config.json`；
4. 均不存在 → 使用内置默认值（此时 db 落在当前工作目录 `./vpsmon.db`）。

读取后逐字段校验并回退默认值（不回写文件）。JSON 解析失败 → 打日志 + 使用默认值（不崩溃，便于首次启动）。

---

## 5. 数据模型与 SQLite

### 5.1 初始化（storage.py `init_db()`）

```sql
PRAGMA journal_mode = WAL;           -- 持久化到库文件
PRAGMA synchronous = NORMAL;         -- WAL 下足够安全，降低写放大
PRAGMA foreign_keys = ON;

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

CREATE INDEX IF NOT EXISTS idx_samples_ts        ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_iface_ts ON samples(iface, ts);
```

- 主键 `(ts, iface)` 防重复写；`idx_samples_ts` 为时间范围查询必需；`idx_samples_iface_ts` 为按网卡+时间查询优化（任务要求的 ts 索引为硬性项，复合索引为推荐项）。
- 采样落库采用 `INSERT OR REPLACE`（同一 ts 冲突时覆盖，保证幂等）。
- 采集线程为唯一写入者；API 线程只读，天然无写冲突。

### 5.2 口径：存储什么、推导什么

- **存储**：`rx_bytes`/`tx_bytes` 为 psutil `net_io_counters` 返回的**内核累计计数**（进程重启后仍从内核续读，不丢失）。
- **推导**：一切速率与区间流量都由相邻样本**正增量**在 Python 层计算（见 §8.1）。**禁止在采集时预先计算并存储"速率"或"区间流量"**——那会引入重启断档与口径漂移。

---

## 6. API 契约

### 6.0 通用约定

- Base：`/api`。除 `GET /`（静态页面）与 `GET /static/*`（前端资源）外，所有 `/api/*` 路由均为 JSON。
- **成功响应统一形状**：`{"ok": true, "data": <对象或数组>}`
- **失败响应统一形状**：`{"ok": false, "error": "<人类可读消息>"}`，配合 HTTP 状态码：
  - `400` 参数缺失/非法；`401` 鉴权失败；`404` 未知路径；`405` 方法不允许；`500` 内部错误（错误详情写入服务端日志，响应体只给通用消息）。
- 所有时间：`ts` 为 Unix 秒（整数）。`time` 字符串为**服务器本地时区**格式 `YYYY-MM-DD HH:MM:SS`（仅作展示辅助；前端图表一律用 `ts` 自行格式化，避免时区歧义）。
- 字节单位一律为**字节（bytes）**，前端负责换算展示（KB/MB/GB）。
- 多网卡端点均接受可选 `?iface=<name>`，缺省 = 当前所选网卡（§8.3 的 `selected`）。

### 6.1 鉴权（token 非空时启用）

- 校验凭据：`X-Token: <token>` 请求头（**默认唯一凭据**）。`?token=<token>` 查询参数**默认拒绝**（`allow_url_token=false`，SECURITY §4.1/H3）：即使值正确也返回 401，防止 token 进入访问日志/浏览器历史/Referer。仅当显式配置 `allow_url_token: true` 时恢复旧行为（二者任一匹配即放行）。
- 比较方式：`hmac.compare_digest` **恒定时间比较**（SECURITY H2），并统一 401 响应体 `{"ok":false,"error":"unauthorized"}`——不区分"缺失 token / 错误 token / 参数位置"，防存在性枚举。
- 安全前置检查顺序（对每个 `/api/*` 请求）：**IP 白名单（`allow_ips` 非空且未命中 → `403 forbidden`）→ 限流（`rate_limit` 超限 → `429 rate_limited`）→ 鉴权（失败 → 401）→ 参数校验（`iface` 非法字符 → `400 invalid iface`）**。
- 作用于**所有** `/api/*` 路由；`GET /` 与静态资源不鉴权（浏览器直接加载页面）。
- 前端行为（js/app.js）：`index.html` 支持 URL `?token=xxx` 自动保存到 `localStorage['vpsmon_token']`；页头提供 token 输入框手动保存/清除；每次 fetch 自动附带 `X-Token` 头；收到 401 时提示重新输入。
- token 为空时前端不附带任何鉴权字段；安装层默认自动生成 token（§9），`--token ""` 可显式不鉴权（警告）。
- 全局安全响应（app.py after_request）：所有响应注入 CSP/X-Frame-Options/nosniff/Referrer-Policy/Permissions-Policy；`/api/*` 强制 `Cache-Control: no-store`；`/` 与 `/static/*` 放宽缓存。Host 头校验：非法结构/未知域名 → `400 invalid host`（SECURITY §4.8，防 DNS rebinding）。

### 6.2 GET /api/status — 系统当前状态

请求参数：无。

响应：

```json
{
  "ok": true,
  "data": {
    "server_time": 1755200000,
    "uptime": 86400,
    "cpu": 12.5,
    "mem":      {"used": 2147483648, "total": 8589934592},
    "disk":     {"used": 10737418240, "total": 53687091200},
    "iface": "eth0",
    "rx_bytes": 1234567890,
    "tx_bytes": 9876543210,
    "latest_ts": 1755199940,
    "sample_count": 1440,
    "db_bytes": 262144
  }
}
```

字段说明：

| 字段 | 含义 |
|---|---|
| `server_time` | 服务器当前 Unix 秒 |
| `uptime` | 系统开机秒数（psutil.boot_time 推导） |
| `cpu` | 当前 CPU%（最近一次采样值） |
| `mem` / `disk` | 字节；实时读取 psutil（不必等下一采样） |
| `iface` | 当前统计网卡 |
| `rx_bytes` / `tx_bytes` | 该网卡内核累计计数（实时读 psutil） |
| `latest_ts` | 最近一次入库样本的时间；空库时为 `null` |
| `sample_count` | 当前网卡样本总数 |
| `db_bytes` | vpsmon.db 文件大小（字节），用于展示数据量 |

### 6.3 GET /api/traffic/monthly — 月度流量（最近 12 个自然月）

请求参数：`?iface=`（可选）。

响应（**固定 12 项，无数据的月份用 0 填充**，便于前端直接画柱状图）：

```json
{
  "ok": true,
  "data": {
    "iface": "eth0",
    "months": [
      {"month": "2025-09", "rx": 0,                "tx": 0},
      {"month": "2025-10", "rx": 123456789,        "tx": 987654321},
      {"month": "2025-11", "rx": 0,                "tx": 0}
    ]
  }
}
```

- `months` 按月份升序，第一项为 11 个月前，最后一项为**当月**（含进行中的部分月）。
- `rx`/`tx` = 该月内**正增量之和**（§8.1 算法），单位字节。
- 当月尚未产生任何样本（空库）→ 该月为 0，`months` 仍为 12 项。

### 6.4 GET /api/traffic/daily?month=YYYY-MM — 指定月份每日流量

请求参数：

| 参数 | 必填 | 说明 |
|---|---|---|
| `month` | 是 | 格式 `YYYY-MM`。缺失/格式非法 → `400 {"ok":false,"error":"invalid month, expect YYYY-MM"}` |
| `iface` | 否 | 网卡名 |

响应（**固定为当月全部天数，无数据天用 0 填充**）：

```json
{
  "ok": true,
  "data": {
    "month": "2026-08",
    "iface": "eth0",
    "days": [
      {"day": "2026-08-01", "rx": 0, "tx": 0},
      {"day": "2026-08-02", "rx": 12345678, "tx": 98765432},
      {"day": "2026-08-03", "rx": 0, "tx": 0}
    ]
  }
}
```

- `days` 按日期升序；天数为该自然月实际天数（含大小月/闰年）。
- **增量归属规则**：样本与其数据库内全局前驱做差，增量计入**终点样本 ts 所在的那一天**（跨天边界的增量全部归属终点日）。

### 6.5 GET /api/traffic/live — 实时速率与近期趋势

请求参数：

| 参数 | 必填 | 说明 |
|---|---|---|
| `minutes` | 否 | 趋势时间窗（分钟），默认 30，范围 5–1440，非法回退 30 |
| `iface` | 否 | 网卡名 |

响应：

```json
{
  "ok": true,
  "data": {
    "iface": "eth0",
    "rx_rate": 1234.5,
    "tx_rate": 567.8,
    "stale_sec": 3,
    "series": [
      {"ts": 1755199700, "rx_rate": 1000.0, "tx_rate": 500.0},
      {"ts": 1755199760, "rx_rate": 1234.5, "tx_rate": 567.8}
    ]
  }
}
```

- `rx_rate`/`tx_rate`：最近两个样本的正向差值与时间差之比（bytes/s），见 §8.4；不足两个样本时二者为 `0.0`。
- `series`：时间窗内（`ts >= now - minutes*60`）按 ts 升序的速率序列，每个点 = 该样本与其前驱的速率（首点无前驱 → 0）。空库 → `series: []`。
- `stale_sec`：`server_time - latest_ts`，表示数据新鲜度；空库时为 `null`。前端据此显示"数据正常/延迟/无数据"。

### 6.6 GET /api/history — 最近样本明细（表格）

请求参数：

| 参数 | 必填 | 说明 |
|---|---|---|
| `limit` | 否 | 返回条数，默认 100，范围 1–1000，非法回退 100 |
| `iface` | 否 | 网卡名 |

响应：

```json
{
  "ok": true,
  "data": {
    "iface": "eth0",
    "samples": [
      {
        "ts": 1755199940,
        "time": "2026-08-15 04:32:20",
        "rx_bytes": 1234567890,
        "tx_bytes": 9876543210,
        "rx_rate": 1234.5,
        "tx_rate": 567.8,
        "cpu": 12.5,
        "mem_used": 2147483648,
        "mem_total": 8589934592,
        "disk_used": 10737418240,
        "disk_total": 53687091200
      }
    ]
  }
}
```

- 按 `ts` **倒序**（最新在前）。
- `rx_rate`/`tx_rate`：该样本与其前驱的速率；最新一条样本与上一条计算，无前驱则为 `0.0`。
- 空库 → `samples: []`。

### 6.7 GET /api/interfaces — 网卡列表

请求参数：无（不鉴权豁免，仍受 token 约束）。

响应：

```json
{
  "ok": true,
  "data": {
    "selected": "eth0",
    "interfaces": [
      {"name": "eth0", "rx_bytes": 1234567890, "tx_bytes": 9876543210, "is_selected": true},
      {"name": "eth1", "rx_bytes": 0, "tx_bytes": 0, "is_selected": false}
    ]
  }
}
```

- 列出所有**非回环、非虚拟**网卡（过滤规则见 §8.3），按累计字节数降序；`rx_bytes`/`tx_bytes` 为内核当前累计计数。
- `selected` 为当前统计网卡；`is_selected` 与之对应。
- （可选扩展，本期可不做）`POST /api/interfaces/select {"iface": "eth1"}`：切换统计网卡并重写 config.json 的 `iface` 字段。

---

## 7. 模块边界与内部接口

| 模块 | 职责 | 关键函数/接口 | 依赖 |
|---|---|---|---|
| `config.py` | 配置加载、校验、回退 | `load_config(cfg_path=None) -> dict` | 仅 stdlib |
| `storage.py` | SQLite 初始化与全部查询；**正增量聚合算法** | `Storage(db_path)`：`init_db()`、`insert_sample(rec)`、`close()`；`monthly(iface)`、`daily(iface, month)`、`live(iface, minutes)`、`history(iface, limit)`、`status_meta(iface)`、`list_ifaces_with_counts()` | stdlib sqlite3 |
| `collector.py` | 采样循环（独立线程）；网卡自动选择 | `select_iface(counters, prefer=None) -> str`、`Collector.sample_once()`；psutil 缺失自动切 `/proc` 后端 | psutil（可选；缺失用 procmetrics） |
| `procmetrics.py` | **/proc 采集后端**（psutil 语义等价物） | `net_dev()`、`cpu_percent()`（增量）、`meminfo()`、`disk_usage(path)`、`uptime_sec()` | 仅 stdlib（§13.2.1） |
| `security.py` | **框架无关安全原语**（Flask/stdlib 双后端复用） | `client_ip(cfg, remote_addr, headers)`、`ip_allowed(cfg, ip)`、`SlidingWindowRateLimiter`、`authenticate(cfg, headers, query)`、`security_headers(path, is_secure)`、`valid_host(host, bind)` | 仅 stdlib（§13.2.2） |
| `api.py` | **6 端点纯处理器**（`handle_*(cfg, storage, collector, params) -> (code, body)`）+ Flask Blueprint 薄适配层；token 鉴权 | `create_blueprint()`、`handle_status/handle_monthly/handle_daily/handle_live/handle_history/handle_interfaces` | Flask（仅蓝图路径；纯处理器仅 stdlib） |
| `stdserver.py` | **纯标准库 HTTP 服务器**（OpenWrt 后端） | `create_server(cfg, storage, collector)`；`ThreadingHTTPServer` + Handler：路由/安全门/静态文件/TLS/日志脱敏 | 仅 stdlib（§13.2.3） |
| `app.py` | 组装与启动；**后端自动选择** | `main()`：解析 `--config/--db` → load_config → Storage.init_db → 启动采集线程 → Flask（可用时）或 stdlib server | 上述全部（§13.2.2） |

**数据流**：

```
collector（线程）
  └─ 采样后端：psutil（VPS） | procmetrics /proc（OpenWrt）
  └─ storage.insert_sample(rec)          → samples 表（唯一写入者）
HTTP 线程（读）
  └─ 框架适配层：Flask 蓝图 | stdserver.Handler   → security.py 安全门
  └─ api 纯处理器 handle_* → storage.query_* → 正增量聚合 → JSON（两框架字段一致）
```

**线程与生命周期**：`app.py` 用 `threading.Thread(daemon=True)` 启动采集线程；`Storage` 连接 `check_same_thread=False` + 单连接 + 写入用 `threading.Lock()` 保护（防御性，实际仅采集线程写）；进程退出时 `Storage.close()`。

---

## 8. 关键算法与边界

### 8.1 正增量求和（月度/日度流量核心）

原则：**只累加 `Δ > 0` 的增量，忽略负增量与零增量**。

```
给定区间 [T0, T1) 内的样本集 S（按 ts 升序）：
  取 S 中每行 cur，及其“数据库全局前驱”（同一 iface、ts 严格小于 cur.ts 的最近一行 prev，可能落在区间外）
  Δrx = cur.rx_bytes - prev.rx_bytes
  Δtx = cur.tx_bytes - prev.tx_bytes
  if Δrx > 0: 区间流量 += Δrx        # Δ<=0 视为计数器重置/网卡更换，丢弃
  if Δtx > 0: 区间流量 += Δtx
  增量归属区间内 cur 所在的天/月
```

- 区间第一个样本的前驱在区间外属正常：其增量（跨边界的流量）计入终点所在天/月，这是可解释且稳定的口径。
- 实现（storage.py）：按 `(iface, ts)` 取区间样本后**在 Python 层线性扫描**（SQLite 只负责取数）。样本量小（60s 间隔一年约 52 万行），扫描毫秒级，避免对 SQLite 版本（窗口函数需 3.25+）的依赖。
- 正增量求和天然免疫：进程重启（计数仍单调）、网卡重插/重置（计数回 0 → 负增量被丢弃）、系统重启。

### 8.2 空库与首次运行

- 首次启动：建表 → 自动选网卡 → 首条样本入库（该样本无前驱，任何统计都视为增量起点）。
- 所有统计端点空库行为：`months`/`days` 按日历补 0 返回；`series`/`samples` 返回空数组；`rx_rate`/`tx_rate` 返回 0.0；`latest_ts` 返回 null。**前端必须对空库有明确展示**（"等待首个采样点…"，约 interval 秒后出现数据）。
- 采集线程预热：启动时先调一次 `psutil.cpu_percent(interval=None)`（返回无意义值），从第二轮起返回真实间隔均值。

### 8.3 多网卡选择

`select_iface()` 规则（确定性）：

1. 候选集 = `psutil.net_io_counters(pernic=True)` 中所有网卡；
2. 排除：`lo`、名字以 `veth`/`docker`/`br-`/`virbr`/`tun`/`tap`/`vbox`/`vmnet` 开头的虚拟网卡、当前 `rx+tx == 0` 的网卡（从未有流量的）；
3. 若候选为空（全虚拟/全零），放宽为所有非 `lo` 网卡中 `rx+tx` 最大者；
4. 最终取 `rx+tx` **累计字节最大**的网卡（VPS 通常即主网卡 eth0/ens3）；
5. 若 config.iface 非空：优先使用之；**每轮采样校验其仍在候选集内**，若消失（改名/拔线）→ 回退到自动选择并打日志、更新运行态 `selected`（不重写 config.json）。

### 8.4 实时速率

```
rate = (cur_bytes - prev_bytes) / (cur_ts - prev_ts)   # bytes/s
```

- `cur`/`prev` 为同一 iface 相邻样本；无前驱或差值 ≤ 0 → `0.0`。
- 速率天然受 `interval` 平滑：60s 间隔下为 60s 均值，瞬时尖峰被平均；`interval` 调小可提高分辨率（下限 5s）。
- 前端展示换算：`< 1024 → B/s`，`< 1024^2 → KB/s`，`< 1024^3 → MB/s`，否则 `GB/s`（保留 1 位小数）。

### 8.5 时间与时区

- 落库 `ts = int(time.time())`（UTC Unix 秒）。
- 天/月边界按**服务器本地时区**聚合（Python `datetime.fromtimestamp(ts)` 或 SQL `strftime('%Y-%m-%d', ts, 'unixepoch', 'localtime')`）。README 注明：跨时区部署时"日"以服务器本地日为准。
- 月份补 0 与"当月天数"计算均用本地时区的 `calendar` 逻辑实现。

---

## 9. install.sh 步骤大纲（engineer_ops 依据）

脚本行为：`install.sh`（安装）与 `install.sh uninstall`（卸载）。支持参数 `--port`、`--interval`、`--token`、`--iface`、`--keep-data`（覆盖默认写入 config.json），以及环境变量 `VPSMON_PORT`/`VPSMON_TOKEN`（优先级低于同名参数）。安装加固详见 `docs/SECURITY.md` §4.10/§4.11。

**安装流程**：

1. **root 检查**：`EUID != 0` → 提示 `sudo bash install.sh` 并退出 1。
2. **端口解析（不再静默默认 8080，SECURITY M9）**：
   - `--port`/`VPSMON_PORT` 已提供 → 校验 1-65535（纯数字、前导零按十进制），非法退出；
   - 交互模式（`[ -t 0 ]` 为真）→ `read` 提示"请输入监听端口（1-65535）："，非法重试最多 3 次后退出；
   - 非交互/管道模式（stdin 非终端）→ 必须 `--port` 或 `VPSMON_PORT`，否则报错退出并提示用法（含远程一行安装示例），禁止回退默认值。
3. **token 解析（默认自动生成，SECURITY H1/M9）**：
   - 交互模式 → 提示用户输入（留空 = 不开启鉴权，显著警告公网风险；长度 < 8 警告）；
   - 非交互模式未给 `--token` → 自动生成强随机 128bit（`openssl rand -hex 16` → `/dev/urandom`+`od` → `python3 secrets.token_hex(16)` 依次回退）；
   - `--token ""` 显式不鉴权（警告）。
4. **发行版检测**：读 `/etc/os-release` 的 `ID`：
   - `debian`/`ubuntu` → `apt-get`
   - `centos`/`rhel`/`rocky`/`alma`/`fedora` → `dnf`（无 dnf 回退 `yum`）
   - `alpine` → `apk`
   - 未知 → 报错退出并提示手动安装。
5. **安装系统依赖**：`python3`、`python3-venv`、`python3-pip`（apt 包名；dnf 为 `python3 python3-pip`；apk 为 `python3 py3-pip`）。
6. **创建系统用户**：`useradd --system --no-create-home --home-dir /opt/vpsmon --shell /usr/sbin/nologin vpsmon`（已存在则跳过）。
7. **复制程序**：`vpsmon/` 包、`requirements.txt` → `/opt/vpsmon/`。
8. **创建虚拟环境**：`python3 -m venv /opt/vpsmon/venv && /opt/vpsmon/venv/bin/pip install --no-cache-dir -r /opt/vpsmon/requirements.txt`。
9. **权限属主（SECURITY M7）**：`/opt/vpsmon` 归 root:root 只读（`chmod -R o-w` 保底，**不再** `chown -R vpsmon`）；`/var/lib/vpsmon` 700 属主 vpsmon。
10. **数据目录与配置**：`mkdir -p /var/lib/vpsmon && chown vpsmon:vpsmon /var/lib/vpsmon && chmod 700`；生成 `/var/lib/vpsmon/config.json`（端口=上述解析值、interval、token=生成/输入值、自动网卡；**`umask 077` 子 shell 写入消除 644 窗口（SECURITY M6）**，再 `chmod 600`）。
11. **安装 systemd 服务**：`vpsmon.service` → `/etc/systemd/system/vpsmon.service`（加固 unit 见下方，安装时按实际参数渲染 ExecStart）。
12. **启动**：`systemctl daemon-reload && systemctl enable --now vpsmon`。
13. **curl 自检**：`curl -sf http://127.0.0.1:<port>/api/status` 且响应含 `"ok":true`（token 非空时带 `X-Token` 头）→ 成功；失败 → 输出 `journalctl -u vpsmon -n 50 --no-pager` 提示并退出 1。
14. **防火墙自动放行（SECURITY M10，交互确认）**：检测 `ufw`（`Status: active`）或 `firewalld`（`is-active`）启用状态；端口未放行时交互询问 `是否放行 <port>/tcp？[y/N]`，同意则执行 `ufw allow <port>/tcp comment 'vpsmon'` / `firewall-cmd --permanent --add-port=<port>/tcp && --reload`，并把规则写入标记文件 `/var/lib/vpsmon/.firewall-rule`（`ufw|<port>` 或 `firewalld|<port>`，600）。非交互模式只提示不自动放行；放行失败仅警告不中断。
15. **成功输出**：访问地址（探测公网 IP，`hostname -I`/`curl ifconfig.me` 兜底）、监听端口、token（仅显示一次，提示妥善保存；未设置时醒目警告）+ 安全提示区（勿公开分享 token 与地址、建议安全组/防火墙仅放行来源 IP、忘记 token 如何找回、用 `X-Token` 头避免 URL 泄露）。

**卸载流程（`install.sh uninstall` / `uninstall.sh`）**：

1. `systemctl disable --now vpsmon`（存在时）；
2. **撤销安装时自动添加的防火墙规则（SECURITY S3）**：读 `/var/lib/vpsmon/.firewall-rule` → `ufw delete allow <port>/tcp` / `firewall-cmd --permanent --remove-port=<port>/tcp && --reload` → 删除标记文件；标记缺失则不撤销（避免误删用户既有规则）；
3. `rm -f /etc/systemd/system/vpsmon.service && systemctl daemon-reload`；
4. 交互确认后 `rm -rf /opt/vpsmon /var/lib/vpsmon`；提供 `--keep-data` 标志保留 `/var/lib/vpsmon`；远程管道模式（stdin 非终端）默认保留数据目录；
5. 删除用户 `vpsmon`（`userdel vpsmon`，失败仅警告）。

**vpsmon.service 模板**（install.sh 内嵌渲染，加固版见 SECURITY.md §4.9）：

```ini
[Unit]
Description=VPS Monitor - traffic statistics web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vpsmon
Group=vpsmon
ExecStart=/opt/vpsmon/venv/bin/python /opt/vpsmon/app.py --config /var/lib/vpsmon/config.json
WorkingDirectory=/opt/vpsmon
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vpsmon
UMask=0077
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectClock=true
ProtectProc=invisible
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
PrivateDevices=true
CapabilityBoundingSet=
SystemCallArchitectures=native
RemoveIPC=true
RestrictNamespaces=true
# MemoryDenyWriteExecute=true  # 与 CPython/libffi（psutil C 扩展）不兼容，勿启用
# ProcSubset=pid               # psutil 依赖完整 /proc，勿启用
# PrivateUsers=true            # 改变属主映射语义，勿启用
# IPAddressDeny=any            # 阻断监听 socket 绑定，勿启用

[Install]
WantedBy=multi-user.target
```

> 说明：`app.py` 必须对 `SIGTERM` 有干净退出（Flask 开发服务器默认处理；采集线程为 daemon 线程不阻塞退出）。systemd `ProtectSystem=strict` 下 `/opt/vpsmon`（root:root）只读、仅数据目录可写（SECURITY M7/M8）。

---

## 10. 风险与取舍

| # | 风险/取舍 | 影响 | 缓解 |
|---|---|---|---|
| 1 | 计数器重置无法与真实流量回滚区分 | 重置窗口的流量被少计（正增量丢弃） | 口径保守可解释；README 说明"重置期间不计" |
| 2 | 停机/采集间隙流量丢失 | 服务停止期间的流量不在库里 | 无法避免（psutil 只给当前累计）；缩短 interval 降低粒度；文档说明 |
| 3 | 采样间隔平滑速率 | 瞬时尖峰被平均，速率图偏"平均线" | interval 下限 5s 可调；live 接口给 30 分钟趋势 |
| 4 | 单网卡统计 | 多网卡 VPS 只反映所选网卡 | 自动选最大流量网卡 + `?iface=` 查询参数；多网卡汇总列为扩展 |
| 5 | token 出现在 URL（?token=） | 泄露进访问日志/代理日志 | 文档推荐 X-Token 头；生产建议 Nginx 反代 + HTTPS |
| 6 | Flask 内置服务器性能 | 并发高时吞吐受限 | 单用户监控场景足够；预留 WSGI 替换（API 不变） |
| 7 | SQLite 单机写放大 | 长期运行库文件增长 | WAL + NORMAL；`keep_days` 清理扩展；52 万行/年规模无压力 |
| 8 | 本地时区聚合 | 服务器换时区会移动历史边界 | 文档声明口径；绝大多数 VPS 时区固定 |
| 9 | ECharts 本地 vendor 体积 | 仓库多 ~1MB | 换来 VPS 无外网时 UI 可用，值得 |
| 10 | 磁盘统计仅 '/' | 挂载盘/容器场景不准 | 文档说明；`disk_path` 扩展候选 |
| 11 | psutil 网卡名跨发行版不同 | eth0/ens3/enp0s3 命名差异 | 自动选择不依赖名字，只依赖累计字节数 |

**已决策（不做）**：用户多账户体系、告警通知、历史数据导出、docker 化安装（本期范围外，可作为后续版本）。

---

## 11. 测试要点（供 reviewer 与后端自测参考）

1. **冒烟**：空库启动 → `GET /api/status` ok；等待 ≥ 2 个 interval 后 `/api/history?limit=10` 有数据；`/api/traffic/monthly` 当月出现非 0（本地产生流量后）。
2. **正增量**：手工向 samples 插入一条"计数回退"行（rx 比前一行小），断言月度/日度统计忽略该负增量。
3. **月度/日度形状**：`months` 恒为 12 项；`days` 项数 = 该月天数（2 月 28/29 验证）；无数据月/天为 0。
4. **daily 边界**：跨天样本（23:59:50 与 00:00:10）增量归属终点日。
5. **鉴权**：token 非空时，无 token / 错 token → 401；`?token=` 与 `X-Token` 均通过；静态页不鉴权。
6. **参数边界**：`month=2026-13`、`month=abc` → 400；`limit=0/1001` → 回退默认；`minutes=1/9999` → 回退 30。
7. **并发**：采集线程写库时并发请求 API 无异常（WAL）。
8. **安装脚本**（Linux 容器/VM 内）：安装→自检通过→访问页面→uninstall 后进程停止、目录清除。
9. **兼容**：Python 3.8 最低版本运行 `app.py` 无语法错误（避免 3.10+ 独有语法）。

---

## 12. 交付物核对清单

- [ ] `vpsmon/config.py` — 配置加载/回退（§4）；探测路径追加 `/etc/vpsmon/config.json`（§13.3）
- [ ] `vpsmon/storage.py` — DDL/WAL/正增量聚合（§5、§8.1）；WAL 失败自动回退 DELETE（§13.5）
- [ ] `vpsmon/collector.py` — 采样循环/网卡选择（§8.2、§8.3）；psutil 缺失切 `/proc`（§13.2.1）
- [ ] `vpsmon/procmetrics.py` — `/proc` 采集后端（§13.2.1）
- [ ] `vpsmon/security.py` — 框架无关安全原语（§13.2.2）
- [ ] `vpsmon/api.py` — 6 端点纯处理器 + Flask 蓝图适配（§6、§13.2.2）
- [ ] `vpsmon/stdserver.py` — stdlib HTTP 服务器（§13.2.3）
- [ ] `vpsmon/app.py` — 组装/启动/--config/--db/后端自动选择（§7、§13.2.2）
- [ ] `vpsmon/static/*` — 仪表盘（§6.1 token 交互、§8.4 单位换算）
- [ ] `install.sh` + `vpsmon.service`（§9）；OpenWrt 分支：opkg/procd/uci（§13.3）
- [ ] `uninstall.sh` — OpenWrt 分支：停服/撤销 uci 规则/清理（§13.3.7）
- [ ] `requirements.txt`（§2）
- [ ] `README.md`（安装/API/时区口径/风险说明；OpenWrt 章节由 reviewer 交付）

---

## 13. OpenWrt 支持（T3 架构设计；T4 运行时 / T5 安装分支的实现依据）

> 目标：在 OpenWrt 路由器上以**纯标准库**运行 vpsmon（无 Flask/psutil/venv/pip/gcc），API 契约（§6）与安全基线（SECURITY.md §4）与 VPS 版**逐字段一致**；安装/卸载走 opkg + procd + uci 分支，数据持久化于 overlay 目录。

### 13.1 平台事实与设计前提

| # | OpenWrt 平台事实 | 对设计的影响 |
|---|---|---|
| 1 | 包管理为 **opkg**（无 apt/dnf/apk） | install.sh 新增 openwrt 分支：`opkg update && opkg install ...`（§13.3.1/§13.3.2） |
| 2 | **无 systemd**；服务由 **procd** + `/etc/init.d` rc.common 脚本管理 | 交付 `/etc/init.d/vpsmon` procd 模板（START=99/STOP=10/`procd_set_param`）；无 systemd 单元、无 journalctl（§13.3.5/§13.4） |
| 3 | python3 需 opkg 安装，且**必须用完整包 `python3`**（`python3-light` 缺 sqlite3/http.server 等模块） | 安装依赖固定为 `python3` 完整包，装后执行 `python3 -c "import sqlite3, http.server"` 校验，失败即报错指引（§13.3.2） |
| 4 | **无 venv/pip 惯例、无 gcc**（无法编译 psutil/flask C 扩展） | 运行时采用**纯标准库双后端**：采集 `/proc`、Web 用 `http.server`；不引入任何编译依赖（§13.2） |
| 5 | `/var` 与 `/tmp` 为 **tmpfs**，重启清空 | 数据/配置目录用 overlay 持久路径 **`/etc/vpsmon`**（不可沿用 `/var/lib/vpsmon`；§13.3.3/§13.3.4） |
| 6 | 防火墙为 **uci firewall**（fw3/firewall4，无 ufw/firewalld） | 安装交互放行走 `uci add firewall rule` + `uci commit firewall` + `/etc/init.d/firewall reload`，标记文件撤销（§13.3.6/§13.3.7） |
| 7 | 设备多为 MIPS/ARM，**小内存（64–256MB）、小 Flash（8–32MB）** | 包体积/采集间隔/线程模型按小内存约束设计（§13.5） |
| 8 | 无系统用户惯例，服务以 **root** 运行 | 不做降权（OpenWrt 惯例），以安全配置与文档说明补偿（§13.5） |

### 13.2 运行时架构：纯标准库双后端（T4 实现依据）

两个正交的解耦面，保证 VPS（Flask+psutil）与 OpenWrt（stdlib）行为一致、逻辑单一来源：

- **采集后端抽象**（数据面）：psutil ↔ `/proc`（procmetrics），由 `collector.py` 按可用性自动选择；
- **框架适配抽象**（HTTP 面）：Flask 蓝图 ↔ stdlib server，二者都调用**同一套纯处理器**（api.py `handle_*`）与**同一套安全原语**（security.py）。

#### 13.2.1 采集后端：`procmetrics.py`（/proc 读取）

psutil 缺失/采集失败时自动启用（`collector.sample_once` 与 `/api/status` 实时读共用同一后端选择函数，如 `metrics_backend()`）。每个函数返回与 psutil 调用**相同形状**的数据：

| procmetrics 函数 | /proc 数据源 | 对应 psutil 调用 | 口径（必须与 psutil 对齐） |
|---|---|---|---|
| `net_dev() -> {iface: {"rx_bytes": int, "tx_bytes": int}}` | `/proc/net/dev` | `net_io_counters(pernic=True)` | 跳过第 1–2 行表头；每行按 `:` 分割取网卡名，右侧字段按空白拆分：**字段 0 = rx_bytes、字段 8 = tx_bytes**；空值防御为 0 |
| `cpu_percent() -> float`（增量，非阻塞） | `/proc/stat` 首行 `cpu ...` | `cpu_percent(interval=None)` | `total = 全部字段和`，`idle = idle + iowait`；**首次调用记录基线并返回 0.0**（与 psutil 首调语义一致），之后 `pct = (1 - Δidle/Δtotal) * 100`，clamp 到 [0, 100] |
| `meminfo() -> {"used": int, "total": int}` | `/proc/meminfo` | `virtual_memory()` | `total = MemTotal`；`used = total - MemAvailable`（内核 3.14+）；无 `MemAvailable`（老内核）回退 `total - (MemFree + Buffers + Cached + SReclaimable)` |
| `disk_usage(path) -> {"used": int, "total": int}` | `os.statvfs(path)` | `disk_usage(path)` | `total = f_blocks * f_frsize`；`used = (f_blocks - f_bfree) * f_frsize`；free = `f_bavail * f_frsize`（与 psutil 口径一致） |
| `uptime_sec() -> int` | `/proc/uptime` 首字段 | `boot_time()` 推导 | `uptime = float(首字段)`；`boot_time = now - uptime` |

约束：

- 任一 /proc 文件读取异常 → 该指标抛异常，沿用 collector 现有"单点失败回退上一轮值"与 api status "回退库内样本"语义，不中断整轮；
- `select_iface` 需兼容 procmetrics 的 dict 形状与 psutil 的 `.bytes_recv/.bytes_sent` 属性形状（T4 归一化为同一可读视图：`getattr(io, "bytes_recv", None) or io.get("rx_bytes", 0)`）；
- `interfaces` 端点无 psutil 时同样用 `net_dev()` 过滤 `lo` 与虚拟前缀（复用 `_VIRT_PREFIXES`），空集回退库内 `list_ifaces_with_counts()`（与现行为一致）。

#### 13.2.2 Web 层解耦：`security.py` + `api.py` 纯处理器

**security.py（框架无关，仅 stdlib 依赖）**——从现有 `api.py`/`app.py` 提取，Flask 蓝图与 stdlib Handler 共同调用，安全行为逐条对齐 SECURITY.md §4：

| 原语 | 语义（与现状逐条一致） |
|---|---|
| `client_ip(cfg, remote_addr, headers) -> str` | 默认 `remote_addr`；配置 `trusted_proxy` 且来源匹配时采信 `X-Forwarded-For` 首段（防 XFF 伪造） |
| `ip_allowed(cfg, ip) -> bool` | allow_ips 空 = 放行；支持 IP/CIDR（IPv4/IPv6），IPv4-mapped IPv6 归并 |
| `SlidingWindowRateLimiter(limit)` | 内存滑动窗口：60s 窗口内最多 `limit` 次/分钟/IP；`0` = 关闭；桶数 > 4096 清理空桶（内存有界） |
| `authenticate(cfg, headers, query) -> bool` | token 空 = 放行；否则 `hmac.compare_digest` 恒定时间比较 `X-Token` 头；`allow_url_token=true` 时追加 `?token=` 兼容；失败统一 401 |
| `security_headers(path, is_secure) -> dict` | CSP/X-Frame-Options/nosniff/Referrer-Policy/Permissions-Policy（工作值与 app.py `_CSP` 一致）；`/api/*` → `Cache-Control: no-store`；`/static/*` → `public, max-age=3600`；`/` → `public, max-age=300`；`is_secure` 时追加 HSTS |
| `valid_host(host_header, bind) -> bool` | 迁移现有 `app._valid_host`（结构校验 + 端口校验 + IP 字面量放行 + 主机名钉扎），防 Host 投毒/DNS rebinding |
| `validate_iface(name) -> bool` / `clamp_int(raw, default, lo, hi)` / `parse_month(month)` | 与现状同一套参数边界（iface 字符集 `^[A-Za-z0-9._-]{1,64}$`；limit 1–1000；minutes 5–1440；month 严格 YYYY-MM） |

**api.py 纯处理器**——6 端点重构为纯函数 `handle_*(cfg, storage, collector, params) -> (status_code, body_dict)`，参数 `params` 为已校验 dict（`iface`/`month`/`limit`/`minutes`）。**响应字段逐字段遵守 §6.0–§6.7**（含空库形状、`time` 展示字段、`stale_sec`、`db_bytes` 等）。安全门（白名单 403 → 限流 429 → 鉴权 401 → 参数校验 400）由适配层在调用处理器前执行，处理器本身只负责取数组装。

- **Flask 蓝图 = 薄适配层**：`request` → `client_ip/headers/args` → security.py 安全门 → 纯处理器 → `jsonify`；
- **stdlib Handler = 薄适配层**：`urlparse + parse_qs` → 同一安全门 → 同一纯处理器 → JSON bytes；
- 这样保证两框架的**鉴权/限流/白名单/参数校验/响应形状**天然一致，改动单一来源。

#### 13.2.3 stdlib HTTP 服务器：`stdserver.py`

`create_server(cfg, storage, collector)` 返回可 start/stop 的服务器对象（selftest 与 app.py 共用）：

| 关注点 | 设计 |
|---|---|
| 服务器 | `http.server.ThreadingHTTPServer`（`daemon_threads=True`、`allow_reuse_address=True`）；HTTP/1.0 默认（每请求一连接，单用户足够；线程廉价，无需 keep-alive 优化） |
| 路由 | 精确路径匹配：`/api/status`、`/api/traffic/monthly`、`/api/traffic/daily`、`/api/traffic/live`、`/api/history`、`/api/interfaces`、`/`、`/static/*`；其余 → 404 JSON `{"ok":false,"error":"not found"}`；非 GET 方法 → 405 JSON |
| 安全门 | 全请求先 `valid_host`（非法 → 400 invalid host）；`/api/*` 按 白名单→限流→鉴权→参数校验 顺序执行（响应体/状态码与 Flask 版逐字一致：`forbidden`/`rate_limited`/`unauthorized`/`invalid iface`/`invalid month, expect YYYY-MM`） |
| 响应头 | `security_headers(path, is_secure)` 全量注入；JSON `Content-Type: application/json; charset=utf-8` |
| 静态文件 | 路径归一化（拒绝 `..` 穿越与绝对路径）；`mimetypes.guess_type`；`nosniff`；只允许 `static/` 目录内文件 |
| 日志 | 覆写 `log_message()`：query string 脱敏为 `?redacted`（复用 `_QueryRedactFilter` 语义）；输出到 `vpsmon.http` logger |
| 超时 | `self.timeout = 30`（慢连接不长期占用线程） |
| 错误处理 | Handler 顶层 try/except → 500 JSON `{"ok":false,"error":"internal error"}` + `log.exception`（不泄堆栈，与 Flask 500 处理一致） |
| TLS | 与 Flask 路径同规则：`ssl_certfile`+`ssl_keyfile` 成对配置且文件存在 → `ssl.SSLContext(PROTOCOL_TLS_SERVER)` 包裹 socket；**配置但文件缺失 → 拒绝以明文启动（退出 1）** |

#### 13.2.4 后端自动选择（app.py）

```
_has_flask(): try import flask → True/False
main(): cfg/存储/采集线程装配逻辑不变 →
    Flask 可用 → 现有 create_app + app.run（行为零变化）
    Flask 不可用 → stdserver.create_server(cfg, storage, collector)（OpenWrt 路径）
```

- 选择仅在启动时判定一次；`--selftest` 在双后端下分别执行（Flask 路径沿用现有断言；stdlib 路径新增等价断言集，见 §13.6）；
- stdlib 路径**任何模块不得在 import 期触碰 flask/psutil**（保证 `python3` 环境缺包时 import 不炸）。

### 13.3 安装设计：install.sh OpenWrt 分支（T5 实现依据）

#### 13.3.1 发行版检测扩展

`detect_distro` 增加 openwrt 分支：`ID=openwrt`（`/etc/os-release`）或存在 `/etc/openwrt_release` 或 `command -v opkg` 命中任一 → `PKG_MGR="opkg"`、`PKG_PY="python3 curl ca-bundle"`（`ca-bundle` 供 GitHub 远程下载与自检的 TLS 证书链）。

#### 13.3.2 依赖安装与模块校验

```
opkg update
opkg install python3 curl ca-bundle     # python3 = 完整包（非 python3-light）
# 装后校验（python3-light 缺 sqlite3/http.server → 立即报错指引）:
python3 -c 'import sqlite3, http.server, json, ssl, socketserver'
```

- 校验失败报错信息必须明确：`检测到 python3 缺 sqlite3/http.server 等模块，请安装完整包: opkg install python3`；
- Python 版本下限沿用 `>= 3.8` 校验；
- 远程一行安装的引导段若系统无 curl，提示 `opkg update && opkg install curl ca-bundle` 后重试（busybox wget 仅作提示性回退，不改变主流程）。

#### 13.3.3 目录布局与数据持久化

```
/opt/vpsmon/            # 程序：仅复制 vpsmon/ 包（无 venv、无 pip install、无编译）
/etc/vpsmon/            # 数据/配置：config.json + vpsmon.db（WAL -wal/-shm 同目录）
/etc/init.d/vpsmon      # procd init 脚本（install.sh 渲染）
```

- **为什么用 `/etc/vpsmon` 而不用 `/var/lib/vpsmon`**：OpenWrt 的 `/var`（常符号链接到 `/tmp`）与 `/tmp` 是 **tmpfs**，重启即清空；`/etc` 位于 **overlay 文件系统**（jffs2/ubifs/overlayfs），重启后保留。数据库与 token 配置丢失会造成流量口径断裂与鉴权失效，必须放 overlay；
- 权限：`/etc/vpsmon` 700、`config.json` 600（沿用 `umask 077` 子 shell 写入，SECURITY M6）；`/opt/vpsmon` 755（root:root，OpenWrt 无降权用户，程序目录只读即可）；
- 不创建系统用户 vpsmon（OpenWrt 无此惯例，服务以 root 运行，见 §13.5）。

#### 13.3.4 配置路径推导适配（config.py）

`PROBE_PATHS` 追加 `/etc/vpsmon/config.json`（顺序：`/var/lib/vpsmon/config.json` → `/etc/vpsmon/config.json` → `./config.json`）；数据库由现有规则自动推导为 `/etc/vpsmon/vpsmon.db`。init 脚本显式传 `--config /etc/vpsmon/config.json`，探测顺序仅作手动运行兜底。

#### 13.3.5 procd init 脚本模板（`/etc/init.d/vpsmon`）

```sh
#!/bin/sh /etc/rc.common
# vpsmon — OpenWrt procd 服务（install.sh 渲染，端口/token 在 /etc/vpsmon/config.json）
START=99
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/python3
    procd_append_param command /opt/vpsmon/vpsmon/app.py
    procd_append_param command --config
    procd_append_param command /etc/vpsmon/config.json
    procd_set_param respawn 3600 5 5      # respawn <阈值s> <超时s> <重试次数>
    procd_set_param stdout 1              # 输出送 logd（logread 可查）
    procd_set_param stderr 1
    procd_set_param env PYTHONUNBUFFERED=1
    procd_set_param env PYTHONDONTWRITEBYTECODE=1   # /opt 只读，禁止写 __pycache__
    procd_close_instance
}
```

- 启动：`/etc/init.d/vpsmon start`；开机自启：`/etc/init.d/vpsmon enable`（生成 `/etc/rc.d/S99vpsmon`）；停止：`stop`；
- 模板由 install.sh 按实际值渲染后 `install -m 755` 落盘（`chmod +x`）；
- 服务以 root 运行（`procd_set_param user` 不设置），与 OpenWrt 惯例一致（§13.5 安全说明）。

#### 13.3.6 uci 防火墙放行（交互确认 + 标记撤销）

沿用 SECURITY §4.10-C 的交互策略（非交互只提示不自动放行）：

```
uci add firewall rule
uci set firewall.@rule[-1].name='vpsmon'
uci set firewall.@rule[-1].src='lan'        # 默认 lan；交互可改 wan/任意
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='<PORT>'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall reload
```

- 放行前先查重（`uci show firewall | grep "name='vpsmon'"` 或按 `dest_port` 匹配）避免重复规则；
- 标记文件：`/etc/vpsmon/.firewall-rule`（600），内容 `uci|<规则段名>`（如 `uci|cfg0123ab`；若段名不可得则记 `uci|vpsmon` 由 name 反查）；
- 卸载撤销：按 name `vpsmon` 定位段 → `uci delete firewall.<段>` → `uci commit firewall` → `reload` → `rm -f` 标记；标记缺失则不撤销（避免误删用户既有规则，与现有 S3 语义一致）。

#### 13.3.7 卸载分支（install.sh uninstall / uninstall.sh 的 OpenWrt 分支）

1. `/etc/init.d/vpsmon stop`（存在时）；
2. `/etc/init.d/vpsmon disable`（删除 rc.d 链接）；
3. 撤销 uci 防火墙规则（§13.3.6，在删数据目录之前执行以读取标记）；
4. `rm -f /etc/init.d/vpsmon`；
5. `rm -rf /opt/vpsmon`；
6. 数据目录 `/etc/vpsmon`：`--keep-data` 保留；否则交互确认（默认保留；非交互强制保留）；
7. **不卸载 python3/curl/ca-bundle 等 opkg 包**（可能被其他包依赖，卸载第三方包超出本应用职责）。

#### 13.3.8 端口/token 交互复用

`resolve_port` / `resolve_token_prompt` / `generate_token` / `validate_interval` **原样复用现有逻辑，不重复实现**：非交互管道模式必须 `--port`/`VPSMON_PORT`；token 默认自动生成强随机 128bit；`--token ""` 显式不鉴权（醒目警告）。自检命令：`curl -fsS -H "X-Token: <token>" http://127.0.0.1:<PORT>/api/status | python3 -c 'import sys, json; sys.exit(0 if json.load(sys.stdin).get("ok") else 1)'`——判据为 **JSON 真解析（格式无关）**：python3 解析顶层 `ok` 字段为真即通过。Flask 3.x `jsonify` 输出紧凑 JSON（`"ok":true` 无空格），旧 `grep -q '"ok": true'`（带空格）永假，导致服务正常却被误判"自检失败、安装未完全成功"，故不再使用文本匹配。

### 13.4 运维说明（procd / logread）

| 操作 | 命令 |
|---|---|
| 状态 | `/etc/init.d/vpsmon status`（procd 输出 running/not running 及 PID） |
| 启动/停止/重启 | `/etc/init.d/vpsmon start` / `stop` / `restart` |
| 开机自启（启用/禁用） | `/etc/init.d/vpsmon enable` / `disable` |
| 查看日志 | `logread | grep vpsmon`（logd 环形缓冲）；`logread -f` 实时跟随 |
| 重启后自检 | `curl -H "X-Token: <token>" http://127.0.0.1:<PORT>/api/status` |
| 数据持久性验证 | `df -h /etc`（overlay）；重启后 `/etc/vpsmon/vpsmon.db` 仍在 |

- 无 systemd：不存在 `systemctl`/`journalctl`；procd 的 `status` 与 logd 的 `logread` 是等效入口；
- procd `respawn` 参数保证进程异常退出自动拉起（阈值 3600s 内最多 5 次重启，间隔 5s），与 systemd `Restart=always` 语义对齐。

### 13.5 风险与取舍（OpenWrt）

| # | 风险/取舍 | 影响 | 缓解 |
|---|---|---|---|
| 1 | **python3 完整包体积**（opkg 压缩约 3–6MB，安装后依架构 10–20MB+） | 小 Flash（8MB）设备可能装不下，挤占 overlay | 文档明确要求 **≥16MB 可用 Flash**；安装前 `df -h /` 检查并在不足时明确报错提示（不静默）；T5 验收含该检查 |
| 2 | **无 TLS 部署惯例**（证书工具非默认；stdlib ssl 可用但需自签） | WAN 暴露时 token 与流量数据明文可嗅探 | 默认建议 `bind=127.0.0.1` 或 LAN 网段 + token + `allow_ips` 收敛；WAN 访问走反向代理（opkg 安装 nginx/HAProxy + ACME）或自签证书（`opkg install openssl-util` 后按 SECURITY §4.5 生成）；文档明确"不建议直接公网明文暴露" |
| 3 | **小内存（64–256MB 常见）**：ThreadingHTTPServer 每连接一线程；SQLite WAL 写放大 | 并发连接多时内存紧张；高写频加剧 Flash 磨损 | 单用户监控场景线程开销可忽略；默认 `interval=60`（下限仍为 5 但文档建议 ≥60）；`rate_limit=60` 默认限制查询放大；可选 `keep_days` 清理控制库增长（§10 既有扩展） |
| 4 | **root 运行、无降权**（OpenWrt procd 惯例，无 vpsmon 系统用户） | HTTP 服务被攻破即获得 root | 安全配置补偿：token 安装时**强制默认生成**、`allow_ips` 白名单收敛、`bind` 收紧、限流；文档醒目说明"OpenWrt 上服务以 root 运行，仅供可信网络/本机使用"；后续可选扩展 `procd_set_param user`（busybox adduser 建降权用户），本期不做 |
| 5 | **overlay 闪存磨损**（样本持续写 /etc/vpsmon/vpsmon.db） | 长期高频写入缩短 Flash 寿命 | interval ≥ 60s 降低写频；SQLite WAL 在 overlay（jffs2/ubifs）一般可用，若 `-shm`/mmap 异常则 T4 在 `storage.init_db` 内 try/except 自动回退 `journal_mode=DELETE`（不新增配置项）；`keep_days` 可选 |
| 6 | **误装 python3-light**（缺 sqlite3/http.server 等） | 启动即 ModuleNotFoundError | install.sh 固定安装完整 `python3` + 装后 `import` 校验（§13.3.2），失败给明确指引 |
| 7 | **uci 规则误删风险**（卸载撤销） | 误删用户既有同名规则 | 标记文件 `uci|<段名>` 精确撤销 + 按 name 匹配校验 + 标记缺失不撤销（沿用现有 S3 安全语义） |

### 13.6 任务边界与验收标准

#### T4 边界（后端：标准库运行时）

**范围**：新增 `vpsmon/procmetrics.py`、`vpsmon/security.py`、`vpsmon/stdserver.py`；修改 `collector.py`（psutil 缺失自动切 /proc）、`api.py`（纯处理器抽取 + Flask 薄适配）、`app.py`（双后端选择 + selftest 扩展）、`storage.py`（WAL 失败回退 DELETE）；**不做** install.sh/init 脚本/uci（T5）、README（reviewer）。

**验收**：

1. 无 flask/psutil 环境（`pip uninstall` 或纯净 python3）下 `python -m vpsmon.app --port <p> --selftest` 全部通过（stdlib 后端自检含安全断言）；
2. 6 端点响应与 Flask 版**逐字段一致**（双后端跑同一组 fixtures 断言 JSON 相等）；安全行为等价：无/错 token → 401、超限 → 429、白名单外 → 403、非法 iface/month → 400、未知路径 → 404、非 GET → 405、非法 Host → 400、安全头全量（CSP/XFO/nosniff/Referrer/Permissions/Cache-Control）、query 脱敏不出日志；
3. `/proc` 采集真实数据：`/api/status` 的 cpu/mem/disk/uptime/rx_bytes/tx_bytes 与 `cat /proc/stat`、`/proc/meminfo`、`/proc/net/dev`、`/proc/uptime` 手工核算一致（±可接受误差）；`/api/interfaces` 列出非回环、非虚拟网卡；
4. Python 3.8 兼容；stdlib 路径 import 期不触碰 flask/psutil；
5. TLS：stdlib 服务器证书齐全 → HTTPS 可访问且下发 HSTS；证书缺失 → 拒绝启动（退出 1）；
6. Flask 路径回归：现有全部 selftest 保持通过（双模式互不破坏）。

#### T5 边界（运维：install.sh OpenWrt 分支）

**范围**：修改 `install.sh`（detect_distro 分支、opkg 依赖与校验、目录布局、procd 模板渲染、enable+start+curl 自检、uci 放行与标记、卸载分支）、`uninstall.sh`（OpenWrt 分支）、`config.py`（`PROBE_PATHS` 追加 `/etc/vpsmon/config.json`）；**不做** 运行时 Python 代码（T4）、README（reviewer）。

**验收**：

1. OpenWrt（x86_64 或真实设备）`bash install.sh --port 9090` 全流程：opkg 安装 python3 与模块校验通过、`/opt/vpsmon` 落盘、`/etc/vpsmon/config.json` 权限 600、`/etc/init.d/vpsmon` 渲染正确（START=99/STOP=10/command/respawn/stdout）、`enable` + `start` 后 curl 自检返回 `"ok":true`；
2. **重启后服务自启**（`/etc/rc.d/S99vpsmon` 生效）且 `/etc/vpsmon` 数据保留（overlay 持久性验证）；
3. uci 规则（name=vpsmon）添加成功且标记写入；`install.sh uninstall`/`uninstall.sh` 后：服务停止、rc.d 链接与 init 脚本删除、防火墙规则撤销、`/opt/vpsmon` 删除、数据默认保留、`--keep-data` 生效；
4. 非交互管道模式仍必须 `--port`；token 自动生成并仅本次打印；
5. 仅装 python3-light 的环境 → 安装报错并给出安装完整 `python3` 的明确指引；
6. `logread | grep vpsmon` 可见应用日志；`/etc/init.d/vpsmon status` 显示 running；`curl` 自检带 token 通过。
