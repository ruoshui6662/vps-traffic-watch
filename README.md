# VPS 流量统计监控系统（vpsmon）

单机部署的轻量 VPS 流量监控服务：统计所选网卡的**月度入站/出站流量**，同时展示 CPU、内存、磁盘占用与实时速率。一条命令安装，浏览器访问 `http://<IP>:<port>` 即可查看美观的深色仪表盘。

技术栈：**Python 3 + SQLite + ECharts**。Web 与采集为**双后端自动选择**——Flask/psutil 可用时走标准路径（VPS）；无 Flask/psutil 时自动降级**纯标准库**（`/proc` 采集 + `http.server`，OpenWrt 路由器 / NAS 等精简环境），6 个 API 端点与安全行为两后端**逐字段一致**。采集线程每 `interval` 秒写入一条样本，API 只读；一切速率与月度/日度流量由查询时基于内核累计计数**正增量**推导，天然免疫计数器重置与进程重启。

---

## 功能特性

- 📊 **月度流量统计**：近 12 个自然月入站/出站柱状图（无数据月份自动补 0）
- 📈 **实时速率**：近 30 分钟入站/出站速率折线图（B/s ~ TB/s 自适应单位）
- 🖥️ **系统状态**：CPU 使用率、内存/磁盘占用仪表盘与进度条
- 🗄️ **历史明细**：最近样本表格数据（含速率、CPU、内存、磁盘）
- 🔐 **Token 鉴权**：安装时自动生成强随机令牌（默认仅 `X-Token` 请求头，`?token=` 参数默认禁用防日志泄露），恒定时间比较防时序侧信道
- 🧵 **低资源占用**：SQLite WAL 单写多读；60 秒间隔一年约 52 万行，查询毫秒级
- 🛡️ **systemd 托管**：开机自启、崩溃自动重启、安全加固（`ProtectSystem=strict` + 最小能力集）
- 🚀 **OpenWrt / NAS 支持**：无 Flask/psutil 时自动降级纯标准库后端（`/proc` 采集 + `http.server`，零编译依赖）；OpenWrt 上经 **opkg + procd + uci** 一键安装（见"OpenWrt 路由器支持"章节）
- 🌐 **零外网依赖**：ECharts 本地托管，VPS 无外网也能完整渲染

## 系统要求

| 平台 | 要求 | 说明 |
|---|---|---|
| Linux VPS（Debian/Ubuntu/CentOS/Alpine 系） | Python ≥ 3.8 + pip/venv | systemd 托管；单元按目标 systemd 版本分档生成（≥219 通用档 / ≥230 增强档 / ≥244 完整档），版本不足的加固指令不会写入单元 |
| OpenWrt 路由器（opkg/procd/uci） | **完整版** `python3`（含 sqlite3/http.server）+ 可用 Flash **≥ 16MB** | 纯标准库运行，无 pip/venv/gcc 编译依赖（见"OpenWrt 路由器支持"章节） |
| NAS 等无 Flask/psutil 环境 | Python ≥ 3.8 | 自动降级纯标准库模式：采集走 `/proc`（procmetrics）、Web 走 `http.server`（stdserver），API 契约与安全基线不变（docs/SPEC.md §13） |
| Windows（开发调试） | Python ≥ 3.8 | 可直接运行调试；psutil 缺失时系统状态回退库内最近样本，采集/页面可用 |

> **双后端自动选择**：启动时探测 Flask——可用 → Flask 路径；不可用 → 纯标准库路径。两后端共用同一套 `api` 纯处理器与 `security` 安全原语，6 个端点响应（含空库形状、错误体）**逐字段一致**（docs/SPEC.md §13.2）。

## 界面截图

> TODO：部署后在 `docs/screenshots/` 放置仪表盘截图（本月流量卡片、速率折线图、月度柱状图、系统仪表盘）。

---

## 快速开始

### 一键安装（Linux，推荐）

两种方式任选其一：**远程一行安装**（推荐，从 GitHub 直接拉取）或**本地安装**（项目目录已在服务器上）。

#### 方式一：远程一行安装（推荐）

项目托管于 GitHub（仓库 [`ruoshui6662/vps-traffic-watch`](https://github.com/ruoshui6662/vps-traffic-watch)），在服务器上执行：

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh)"
```

> `install.sh` 已内置默认仓库 `ruoshui6662/vps-traffic-watch`，无需任何配置。脚本默认从 **main 分支**下载仓库 tarball；若仓库默认分支为 `master` 等，需同步修改 `install.sh` 中 `fetch_remote_source` 的 tarball 地址分支名。

Fork 自建或改用其他仓库时，可用环境变量覆盖仓库信息（优先级最高），或用管道方式执行（**管道模式 stdin 非终端，必须显式指定端口**）：

```bash
sudo REPO_OWNER=ruoshui6662 REPO_NAME=vps-traffic-watch bash -c "$(curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh)"
# 或（管道模式必须带 --port，否则报错退出）:
curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh | sudo bash -s -- --port 9090
```

> 供应链说明：`curl | bash` 等于无条件信任脚本内容（任何 GitHub 仓库被接管都会导致 root 失陷）。建议固定 commit：`https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/<commit-sha>/install.sh`；或设置 `VPSMON_EXPECTED_SHA256=<发布方公布的 tarball 校验和>`，下载后自动比对，不匹配立即退出。详见 [docs/SECURITY.md](docs/SECURITY.md) §4.11。

远程模式下脚本自动从 GitHub 下载仓库源码后完成全部安装步骤（临时文件用后即清，不会残留）。

#### 方式二：本地安装（项目目录已在服务器上）

把项目目录上传/克隆到服务器（例如 `/root/vpsmon`），然后：

```bash
cd /root/vpsmon
sudo bash install.sh                          # 交互安装：提示输入端口；token 自动生成
```

带参数安装：

```bash
sudo bash install.sh --port 9090 --interval 30 --token "MyToken123" --iface eth0
```

| 参数 | 说明 | 默认 |
|---|---|---|
| `--port` | 监听端口（1–65535） | 交互输入；**非交互/管道模式必须显式指定**（`--port` 或 `VPSMON_PORT`），否则报错退出 |
| `--interval` | 采集间隔秒（5–86400） | `60` |
| `--token` | 访问令牌；`--token ""` 显式不鉴权（有公网暴露风险） | **自动生成强随机**（128 bit）；交互安装时可自行输入（留空 = 不鉴权并警告） |
| `--iface` | 统计网卡名，空 = 自动选择流量最大的网卡 | 空 |

安装脚本自动完成：root 检查 → 端口解析（`--port` > `VPSMON_PORT` > 交互输入 > 非交互报错）→ token 解析（`--token`/`VPSMON_TOKEN` > 自动生成）→ 源码来源检测（本地目录 / GitHub 远程下载，支持 `VPSMON_EXPECTED_SHA256` 校验和）→ 发行版检测（apt/dnf/yum/apk；OpenWrt 自动走 opkg 分支，见"OpenWrt 路由器支持"章节）→ 安装 `python3`/`python3-venv`/`pip` → 创建系统用户 `vpsmon` → 复制程序到 `/opt/vpsmon`（root:root 只读，并自动部署卸载脚本 `uninstall.sh`）→ 创建虚拟环境并安装依赖 → 生成配置 `/var/lib/vpsmon/config.json`（`umask 077` 落盘即 600）→ 安装并启动 systemd 服务 → curl 自检 → 防火墙交互确认放行（记录标记，卸载自动撤销）→ 输出访问地址、token（仅本次显示）与安全提示。

安装成功后访问：`http://<服务器IP>:<端口>`（本机测试：`curl -H "X-Token: <token>" http://127.0.0.1:<端口>/api/status`）。

> 公网 IP 探测使用 `curl ifconfig.me`，失败回退 `hostname -I` 第一项。无法从外网访问时请检查云厂商安全组 / ufw / firewalld（安装脚本会交互询问是否放行端口，或按末尾提示手动放行）。

### 手动安装（开发 / 调试，Windows 或 Linux 均可）

```bash
# 1. 安装 Python 依赖（建议虚拟环境）
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. 生成配置文件（可选；不建则用内置默认值：端口 8080/间隔 60/无 token/限流 60/min）
#    手动模式默认不鉴权——公网使用前务必设置 token（见"安全"章节）
cat > config.json <<'EOF'
{"port": 8080, "interval": 60, "token": "", "iface": ""}
EOF

# 3. 启动（数据库默认在配置文件同目录 vpsmon.db；可用 --db 覆盖）
python -m vpsmon.app --config config.json
```

Windows 开发机说明：本仓库源码为跨平台 Python，可直接在 Windows 运行调试；`psutil` 缺失时系统状态会降级回退到库内最近样本，采集停止但页面/API 可用（生产环境请按 requirements.txt 正常安装）。

---

## 配置说明

配置文件 `config.json`（一键安装位于 `/var/lib/vpsmon/config.json`（VPS）或 `/etc/vpsmon/config.json`（OpenWrt），手动运行位于当前目录）：

```json
{
  "port": 8080,
  "interval": 60,
  "token": "",
  "iface": "",
  "keep_days": 0,
  "db_path": "",
  "bind": "0.0.0.0",
  "allow_ips": [],
  "rate_limit": 60,
  "allow_url_token": false,
  "ssl_certfile": "",
  "ssl_keyfile": "",
  "trusted_proxy": ""
}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `port` | int | 8080 | 监听端口；非法值（非 1–65535）回退 8080 |
| `interval` | int | 60 | 采集间隔秒；下限 5，越界回退 60 |
| `token` | string | `""` | 访问令牌；空 = 关闭鉴权，非空 = 开启。一键安装默认自动生成强随机值 |
| `iface` | string | `""` | 统计网卡；空 = 自动选择累计流量最大的非虚拟网卡 |
| `keep_days` | int | 0 | 可选：保留样本天数，0 = 无限（清理为后续扩展） |
| `db_path` | string | 空 | 可选：显式指定数据库路径，覆盖默认推导 |
| `bind` | string | `"0.0.0.0"` | 监听地址；设 `127.0.0.1` 仅本机可访问（配合反代使用） |
| `allow_ips` | array | `[]` | IP 白名单：`1.2.3.4` / `10.0.0.0/8` / `2001:db8::/32`（也接受逗号分隔字符串）；非空时未命中 → 403 |
| `rate_limit` | int | 60 | 限流（次/分钟/IP）；`0` = 关闭；超限 → 429 |
| `allow_url_token` | bool | `false` | 是否允许 `?token=` 参数鉴权（默认禁用防日志泄露，建议保持 false） |
| `ssl_certfile` / `ssl_keyfile` | string | 空 | TLS 证书/密钥路径，成对配置且文件存在时启用 HTTPS（详见"安全"章节） |
| `trusted_proxy` | string | 空 | 信任的反代地址；配置后仅来自该地址的请求采信 `X-Forwarded-For` 首段（限流/白名单取真实客户端 IP） |

配置加载顺序：`--config` 参数 > 环境变量 `VPSMON_CONFIG` > 探测 `/var/lib/vpsmon/config.json` > `/etc/vpsmon/config.json`（OpenWrt）> 当前目录 `./config.json` > 内置默认值。**数据库默认位于配置文件同目录下的 `vpsmon.db`**（例如部署模式 `/var/lib/vpsmon/config.json` → `/var/lib/vpsmon/vpsmon.db`；OpenWrt `/etc/vpsmon/config.json` → `/etc/vpsmon/vpsmon.db`），可用 `--db <path>` 覆盖。

配置文件权限：部署模式下 `config.json` 为 `600`（属主 `vpsmon`，`umask 077` 写入），数据目录 `/var/lib/vpsmon`（OpenWrt 为 `/etc/vpsmon`）为 `700`，token 不会暴露给其他用户。

### 文件位置（部署态）

**Linux VPS（systemd）**：

| 路径 | 内容 |
|---|---|
| `/opt/vpsmon/` | 程序包 `vpsmon/` + `requirements.txt` + 虚拟环境 `venv/` + 卸载脚本 `uninstall.sh` |
| `/var/lib/vpsmon/config.json` | 配置（含 token，权限 600） |
| `/var/lib/vpsmon/vpsmon.db` | SQLite 数据库（WAL 模式，`-wal`/`-shm` 同目录） |
| `/etc/systemd/system/vpsmon.service` | systemd 单元（按目标版本分档生成） |

**OpenWrt（procd，见"OpenWrt 路由器支持"章节）**：

| 路径 | 内容 |
|---|---|
| `/opt/vpsmon/vpsmon/` | 程序包（纯标准库，无 venv/pip） |
| `/etc/vpsmon/config.json` | 配置（含 token，权限 600；overlay 持久） |
| `/etc/vpsmon/vpsmon.db` | SQLite 数据库（WAL；`-wal`/`-shm` 同目录） |
| `/etc/init.d/vpsmon` | procd init 脚本 |

---

## 安全（Security）

完整威胁模型、风险清单与加固依据见 [docs/SECURITY.md](docs/SECURITY.md)。本节为部署与运维视角的速查。

### 默认安全配置（一键安装即生效）

| 项 | 默认行为 |
|---|---|
| 监听端口 | 安装时**交互输入**（1–65535，非法重试 3 次）；非交互/管道模式必须 `--port` 或 `VPSMON_PORT`，否则报错退出（不再静默默认 8080） |
| 访问令牌 | **自动生成强随机 128bit**（`openssl rand -hex 16` → `/dev/urandom`+`od` → `python3 secrets` 三级回退）；仅本次安装输出显示；`--token ""` 可显式不鉴权（会给出醒目警告） |
| 鉴权方式 | 仅 `X-Token` 请求头；`?token=` 参数**默认禁用**（防 token 进访问日志/浏览器历史）；`hmac.compare_digest` 恒定时间比较，统一 401 防枚举 |
| 速率限制 | `rate_limit` 默认 **60 次/分钟/IP**（内存滑动窗口；`0` = 关闭），超限 → `429` |
| IP 白名单 | `allow_ips` 默认空（不限制）；配置后未命中 → `403` |
| 安全响应头 | 全部响应注入 CSP（`script-src 'self'`、`frame-ancestors 'none'` 等）、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`Permissions-Policy`；`/api/*` 强制 `Cache-Control: no-store` |
| Host 头校验 | 非法结构/未知域名 → `400 invalid host`（防 Host 投毒与 DNS rebinding） |
| 访问日志 | werkzeug access log 查询串**脱敏**（`?token=xxx` → `?redacted`），token 不出日志 |
| systemd 加固 | 降权用户 `vpsmon` + `ProtectSystem=strict`（程序目录只读）+ `UMask=0077` + `NoNewPrivileges` + 空 `CapabilityBoundingSet` 等（见 `vpsmon.service`） |
| 程序目录 | `/opt/vpsmon` 归 `root:root` 只读（服务被攻破也无法篡改程序持久化后门） |
| 配置文件 | `/var/lib/vpsmon/config.json` 以 `umask 077` 写入（落盘即 600）、目录 700 |
| 防火墙 | 检测到启用的 ufw/firewalld 时**交互确认**后放行端口并记录标记；卸载时自动撤销（无标记不误删既有规则） |
| 供应链 | requirements 精确 pin（`flask==3.1.3` / `psutil==7.2.2`）；远程安装支持 `VPSMON_EXPECTED_SHA256` 校验 tarball；前端无 CDN 兜底（ECharts 本地 vendor，CSP 严格成立） |

### 安全相关配置项

安全字段（均在 `config.json`，见"配置说明"）：`bind`（监听地址）、`allow_ips`（白名单）、`rate_limit`（限流）、`allow_url_token`（是否允许 `?token=`）、`ssl_certfile`/`ssl_keyfile`（TLS）、`trusted_proxy`（信任的反代地址）、`debug`（恒强制 false）。

### TLS 与反向代理

**方案 A：内置 TLS（自签证书，过渡用）**

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /var/lib/vpsmon/key.pem -out /var/lib/vpsmon/cert.pem \
  -subj "/CN=<服务器IP或域名>"
chown vpsmon:vpsmon /var/lib/vpsmon/{cert,key}.pem
chmod 600 /var/lib/vpsmon/key.pem
```

然后编辑 `/var/lib/vpsmon/config.json` 增加：

```json
{"ssl_certfile": "/var/lib/vpsmon/cert.pem", "ssl_keyfile": "/var/lib/vpsmon/key.pem"}
```

`systemctl restart vpsmon` 后以 `https://` 访问（自签证书有浏览器告警，仅作过渡；证书/密钥缺失会拒绝以明文启动，不会静默降级）。

**方案 B：反向代理 + ACME 正式证书（公网推荐）**

vpsmon 只监听本机（`bind: "127.0.0.1"`），由 Nginx/Caddy 终结 TLS。**注意 Host 校验**：vpsmon 只接受 IP 字面量 / `localhost` / 本机 hostname 的 Host 头，因此反代必须把 Host 改写为后端地址（否则返回 `400 invalid host`）：

nginx：

```nginx
server {
    listen 443 ssl;
    server_name mon.example.com;
    ssl_certificate     /etc/letsencrypt/live/mon.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mon.example.com/privkey.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_set_header Host 127.0.0.1:18080;      # 必须：通过 Host 校验
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

caddy：

```caddy
mon.example.com {
    reverse_proxy 127.0.0.1:18080 {
        header_up Host 127.0.0.1:18080              # 必须：通过 Host 校验
    }
}
```

并配置 `trusted_proxy: "127.0.0.1"`（限流/白名单改用 `X-Forwarded-For` 首段识别真实客户端）。反代场景请务必 `bind: "127.0.0.1"` 并在防火墙仅放行 443，避免绕过反代直连明文 8080。

### 安全 FAQ

**1. token 泄露了怎么办？**
编辑 `/var/lib/vpsmon/config.json` 更换 token 后 `systemctl restart vpsmon`。同时排查泄露路径：`journalctl -u vpsmon | grep -i token`（应为空，日志已脱敏）、浏览器历史/代理日志（`?token=` 已默认禁用）。token 仅存于 600 权限的 config.json，其他本地用户不可读。

**2. 只想本机访问？**
`bind` 设为 `"127.0.0.1"`（配置后重启）。此时无需 token/白名单/TLS，纯本机回环。

**3. 如何限制只有我的 IP 能访问？**
两种方式叠加最稳：① `allow_ips: ["<你的公网IP>"]`（应用层 403）；② 防火墙/云安全组仅放行来源 IP（如 `ufw allow from <你的IP> to any port <port> proto tcp`）。白名单配合 `allow_ips` 生效时，即使忘记 token 也不会裸奔。

**4. 想用域名访问（Host 钉扎）？**
Host 校验只放行 IP 字面量、`localhost`、`::1`、本机 hostname——攻击者控制的任意域名都会被 400 拒绝（防 DNS rebinding）。反代场景按上文把 Host 改写为后端地址即可；也可直接使用 `http://<服务器IP>:<端口>`。

**5. 如何确认加固生效？**
`systemd-analyze security vpsmon` 查看评分；`curl -sI http://127.0.0.1:<port>/ | grep -iE 'content-security-policy|x-frame-options|x-content-type-options|referrer-policy|cache-control'` 检查响应头；`journalctl -u vpsmon | grep -E '\?token='` 应为空；`ls -l /var/lib/vpsmon/config.json` 应为 600。

---

## systemd 管理

```bash
systemctl status vpsmon          # 查看状态
systemctl restart vpsmon         # 重启
systemctl stop vpsmon            # 停止
systemctl start vpsmon           # 启动
journalctl -u vpsmon -f          # 实时查看日志
journalctl -u vpsmon -n 50 --no-pager   # 最近 50 行日志
systemctl disable --now vpsmon   # 停止并取消开机自启
```

---

## OpenWrt 路由器支持

vpsmon 在 OpenWrt 上以**纯标准库**运行（无 Flask/psutil/pip/venv，无需 gcc 编译），由 install.sh 自动识别发行版并走 **opkg/apk + procd + uci** 分支（**opkg 系**：OpenWrt ≤ 23.05；**apk 系**：ImmortalWrt、OpenWrt 24.10+ 等新固件）；API 契约与安全基线（docs/SECURITY.md §4.12）与 VPS 版一致。

### 前置要求

1. **bash**：OpenWrt 默认只有 busybox ash，**必须先安装 bash**（安装脚本为 bash 编写）：
   ```bash
   # opkg 系（OpenWrt ≤ 23.05）:
   opkg update && opkg install bash curl
   # apk 系（ImmortalWrt / OpenWrt 24.10+，opkg 不存在时用 apk）:
   apk update && apk add bash curl
   ```
2. **完整版 python3**：`python3-light` 缺 sqlite3/http.server 等模块（启动即崩），必须安装完整包（install.sh 会自动识别 opkg/apk 并安装、做模块校验）：
   ```bash
   # opkg 系:
   opkg install python3 curl ca-bundle
   # apk 系:
   apk add python3 curl ca-bundle
   python3 -c 'import sqlite3, http.server, json, ssl, socketserver'
   ```
3. **存储空间 ≥ 16MB**：python3 完整包安装后占用 10–20MB+，先 `df -h /` 确认 overlay 可用空间；不足时 install.sh 会明确报错退出（不静默）。

### 安装

**本地安装**（把项目目录放到路由器上，如 `/root/vpsmon`）：

```bash
cd /root/vpsmon
bash install.sh --port 9090 --token "你的令牌"
```

**远程一行安装**（OpenWrt 惯例以 root 直接执行，无需 sudo；**管道模式 stdin 非终端必须显式指定 `--port`**）：

```bash
curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh | bash -s -- --port 9090
```

> `--port` **必填**：OpenWrt 分支沿用 VPS 版端口解析规则——非交互/管道模式不提供 `--port`（或 `VPSMON_PORT`）即报错退出，不静默默认 8080。token 默认自动生成强随机 128bit（仅本次安装输出显示，请妥善保存）。

安装后自检：`curl -H "X-Token: <token>" http://127.0.0.1:9090/api/status` 应返回含 `"ok":true` 的 JSON（Flask 3.x 输出紧凑格式，`"ok"` 与 `true` 间无空格；安装脚本自检判据用 JSON 解析顶层 `ok` 字段，不依赖任何空格/格式）。

### procd 服务管理（替代 systemctl）

OpenWrt 无 systemd，服务由 procd 管理，init 脚本为 `/etc/init.d/vpsmon`（START=99 / STOP=10，`respawn` 崩溃自动拉起，等价 systemd `Restart=always`）：

| 操作 | 命令 |
|---|---|
| 状态 | `/etc/init.d/vpsmon status` |
| 启动 / 停止 / 重启 | `/etc/init.d/vpsmon start` / `stop` / `restart` |
| 开机自启（启用 / 禁用） | `/etc/init.d/vpsmon enable` / `disable` |
| 查看日志 | `logread \| grep vpsmon`（实时：`logread -f \| grep vpsmon`） |

> 无 journalctl：应用与访问日志经 logd 环形缓冲，用 `logread` 查看；访问日志查询串同样脱敏（`?token=xxx` → `?redacted`），token 不出日志。

### 数据目录：/etc/vpsmon（overlay 持久化）

OpenWrt 的 `/var`（常符号链接到 `/tmp`）与 `/tmp` 是 **tmpfs，重启即清空**；因此配置与数据库放在 overlay 文件系统的 **`/etc/vpsmon`**（重启保留），路径如下：

| 路径 | 内容 |
|---|---|
| `/opt/vpsmon/vpsmon/` | 程序包（root:root 只读，无 venv/pip） |
| `/etc/vpsmon/config.json` | 配置（含 token，权限 600） |
| `/etc/vpsmon/vpsmon.db` | SQLite 数据库（WAL；`-wal`/`-shm` 同目录） |
| `/etc/init.d/vpsmon` | procd init 脚本 |
| `/etc/rc.d/S99vpsmon` | enable 生成的开机自启链接 |

持久性验证：重启后 `ls /etc/vpsmon/vpsmon.db` 应仍存在（`df -h /etc` 确认 overlay）。

### 防火墙（uci）

安装时**交互确认**后自动放行（默认仅 `src=lan` 来源，规则 name=vpsmon，段名写入 `/etc/vpsmon/.firewall-rule` 标记，卸载自动精确撤销；非交互模式只提示不放行）。手动放行示例：

```bash
uci add firewall rule
uci set firewall.@rule[-1].name='vpsmon'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='9090'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall reload
```

### 安全建议（OpenWrt 以 root 运行）

OpenWrt 上服务以 **root 运行**（procd 惯例，无降权用户），**仅供可信网络 / 本机使用**。推荐配置（编辑 `/etc/vpsmon/config.json` 后 `/etc/init.d/vpsmon restart` 生效）：

- `"bind": "127.0.0.1"`（纯本机）或路由器 LAN IP（如 `"bind": "192.168.1.1"`）；
- `"allow_ips": ["192.168.1.0/24"]`（应用层 403 兜底，忘记 token 也不裸奔）；
- token 安装时**强制默认生成**，勿外传；忘记可编辑 config.json 后重启；
- uci 防火墙**只放行 lan 来源**，不建议 wan 直接放行；
- WAN 访问必须走反向代理（opkg 装 nginx/HAProxy + TLS）或自签证书（`opkg install openssl-util` 后按 docs/SECURITY.md §4.5 生成），**禁止公网明文 HTTP 暴露**（完整示例见 docs/SECURITY.md §4.12）。

### 卸载

```bash
bash /opt/vpsmon/uninstall.sh                # 卸载（默认保留数据）
bash /opt/vpsmon/uninstall.sh --keep-data    # 显式保留 /etc/vpsmon 数据
```

卸载动作：停止并禁用服务 → 撤销 uci 防火墙规则（标记缺失则不撤销，避免误删用户既有规则）→ 删除 init 脚本与 `/opt/vpsmon` → 按确认/`--keep-data` 决定是否删除 `/etc/vpsmon`（默认保留；非交互强制保留）。**不会卸载 python3/curl/ca-bundle 等 opkg 包**（可能被其他包依赖，超出本应用职责）。

### 已知限制

- **日志方式不同**：无 systemd/journalctl，用 `logread | grep vpsmon`（procd 的 `stdout/stderr` 送 logd）；
- **python3-light 误装排查**：若启动报 `ModuleNotFoundError: sqlite3`/`http.server` 等，说明装成了精简版——执行 `opkg remove python3-light && opkg install python3` 后重跑安装（install.sh 装后即校验，安装阶段就会报错指引）；
- 小内存（64–256MB）设备建议保持 `interval=60`（下限 5）并配合默认 `rate_limit=60`；`/etc/vpsmon` 位于 overlay（jffs2/ubifs），SQLite WAL 不可用时会自动回退 `journal_mode=DELETE`（无需配置）。

---

## API 一览

所有接口位于 `/api`，成功响应统一为 `{"ok": true, "data": ...}`，失败为 `{"ok": false, "error": "..."}`。字节单位一律为 **bytes**（前端负责换算）。多网卡端点支持可选 `?iface=<name>`，缺省 = 当前所选网卡。

| 端点 | 说明 |
|---|---|
| `GET /api/status` | 系统状态：CPU/内存/磁盘、当前网卡计数、最新样本时间、样本数、库大小 |
| `GET /api/traffic/monthly` | 近 12 个自然月入站/出站流量（固定 12 项，无数据补 0） |
| `GET /api/traffic/daily?month=YYYY-MM` | 指定月每日流量（固定当月全部天数）；非法 month → 400 |
| `GET /api/traffic/live?minutes=30` | 实时速率（bytes/s）与近期趋势序列（5–1440 分钟，非法回退 30） |
| `GET /api/history?limit=100` | 最近样本明细（1–1000 条，倒序，含速率与系统指标） |
| `GET /api/interfaces` | 可用网卡列表（排除回环/虚拟网卡，按累计流量降序） |

鉴权：token 非空时，所有 `/api/*` 请求必须携带 `X-Token: <token>` 请求头（`hmac.compare_digest` 恒定时间比较）；`?token=` 参数**默认拒绝**（`allow_url_token=true` 可恢复旧行为，但会把 token 带进访问日志）。无 token/错 token 统一返回 `401 {"ok":false,"error":"unauthorized"}`。`GET /` 与静态资源不鉴权。前端支持 URL `?token=xxx` 自动保存到 `localStorage`，后续请求自动附带 `X-Token` 头，收到 401 时弹出输入框。

安全前置检查（按序）：IP 白名单（`allow_ips` 未命中 → 403）→ 限流（超限 → 429）→ 鉴权（失败 → 401）→ 参数校验（`iface` 非法字符 → 400）。

> 请始终使用 `X-Token` 请求头，不要使用 `?token=`（默认已禁用）。生产环境推荐 Nginx/Caddy 反代 + HTTPS（见"安全"章节）。

---

## 一键卸载

安装成功后，自包含卸载脚本 `uninstall.sh` 已自动部署到 `/opt/vpsmon/uninstall.sh`。以下方式任选其一（行为等价）：

**远程一行卸载**（从 GitHub 直接拉取自包含卸载脚本）：

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/uninstall.sh)"
```

**服务器本地卸载**（安装时已自动部署）：

```bash
sudo bash /opt/vpsmon/uninstall.sh
```

**项目目录内卸载**（本地安装场景）：

```bash
cd /root/vpsmon
sudo bash uninstall.sh
```

> 兼容旧写法：`sudo bash install.sh uninstall` 与 `sudo bash install.sh uninstall --keep-data` 同样可用。

### 卸载内容清单

| 项目 | 路径/名称 | 说明 |
|---|---|---|
| systemd 服务 | `vpsmon.service`（`/etc/systemd/system/`） | 停止并禁用后删除单元，`daemon-reload` |
| 程序目录 | `/opt/vpsmon` | 程序包 `vpsmon/` + `venv/` + `uninstall.sh` 自身（脚本已载入内存，删除不影响执行） |
| 数据目录 | `/var/lib/vpsmon` | `config.json` + `vpsmon.db`；**默认保留**（见下） |
| 系统用户 | `vpsmon` | `userdel vpsmon`（删除失败时提示手动处理） |

> OpenWrt 平台自动走 procd/uci 分支（停止并禁用 `/etc/init.d/vpsmon` → 撤销 uci 防火墙规则 → 删除 init 脚本与 `/opt/vpsmon` → 决定是否删除 `/etc/vpsmon`），详见"OpenWrt 路由器支持"章节的卸载说明。

### 数据目录保留策略

- 交互式卸载会询问 `是否同时删除数据目录 /var/lib/vpsmon ...？[y/N]`：输入 `y` 删除，回车或其他键**默认保留**；
- `sudo bash uninstall.sh --keep-data`（或 `install.sh uninstall --keep-data`）跳过询问、直接保留数据；
- 远程管道执行（`curl ... | sudo bash`）时 stdin 不是终端，**自动跳过确认并默认保留数据目录**，如需一并删除请手动执行 `sudo rm -rf /var/lib/vpsmon`。

卸载流程：停止并禁用服务 → 删除 systemd 单元并 `daemon-reload` → 删除 `/opt/vpsmon` → 按确认/`--keep-data` 决定是否删除 `/var/lib/vpsmon` → 删除系统用户 `vpsmon`。

---

## 常见问题（FAQ）

**1. 浏览器无法访问，提示超时/拒绝连接？**

- 先在本机确认：`curl -H "X-Token: <token>" http://127.0.0.1:<port>/api/status` 应返回 `"ok":true`（未设置 token 时省略请求头；token 可在安装输出中查看或从 `/var/lib/vpsmon/config.json` 读取）。
- 本机正常、外部不通 → 防火墙未放行：`sudo ufw allow <port>/tcp`（ufw）或 `sudo firewall-cmd --permanent --add-port=<port>/tcp && sudo firewall-cmd --reload`（firewalld）；云服务器还需在**安全组**入方向放行 TCP 端口。

**2. 端口被占用（Address already in use）？**

```bash
ss -lntp | grep <port>     # 找出占用进程
sudo systemctl restart vpsmon   # 或改用其他端口重新安装
```

**3. 服务器有多个网卡，统计的是哪块？**

默认自动选择**累计流量最大**的非虚拟网卡（排除 `lo`、`veth*`、`docker*`、`br-*`、`virbr*`、`tun*`、`tap*`、`vbox*`、`vmnet*`）。如需固定某块网卡：重新安装时加 `--iface <网卡名>`，或编辑 `/var/lib/vpsmon/config.json` 的 `iface` 字段后 `sudo systemctl restart vpsmon`。API 查询也可临时用 `?iface=<name>` 指定。配置的网卡失效（改名/拔线）时自动回退到流量最大的网卡，不影响服务。

**4. Ubuntu/Debian 提示 `ensurepip is not available` 或 venv 创建失败？**

缺少 `python3-venv` 组件：

```bash
sudo apt install -y python3-venv
```

然后重新执行 `sudo bash install.sh`（脚本会自动安装该包；若为手动安装，删除 `.venv` 后重建）。

**5. 忘记 token 怎么办？**

编辑 `/var/lib/vpsmon/config.json`，将 `token` 改为空字符串或新值，然后 `sudo systemctl restart vpsmon`。

**6. 图表显示"等待首个采样点…"？**

正常现象：服务启动后约一个 `interval`（默认 60 秒）才有第一条样本，之后页面 5 秒刷新一次自动出现数据。

**7. 为什么"本月流量"比我实际用的少？**

统计口径是**正增量**：只累加相邻样本间的正向差值。计数器重置/网卡更换窗口的流量会被丢弃（无法与真实回滚区分，属保守且可解释的口径）；服务停止期间的流量也不会入库（psutil 只提供当前累计值）。缩短 `interval` 可降低粒度。

**8. 统计的"日/月"按什么时区？**

按**服务器本地时区**聚合（`day`/`month` 字段与数据库样本的本地时间展示一致）。跨时区部署时请以服务器本地日为准。

**9. 磁盘占用统计的是哪块盘？**

固定统计根分区 `/`。有多个挂载盘/容器场景可能不准（后续版本预留 `disk_path` 扩展）。

**10. 需要更高的并发/性能？**

单用户监控场景 Flask 内置服务器足够；API 与存储解耦，未来可无改动替换为 gunicorn/waitress 等 WSGI 服务器。

**11. 远程一键安装失败怎么办？**

按顺序排查：

- **curl 缺失**：`command -v curl` 无输出则先安装（`apt-get install -y curl` / `dnf install -y curl` / `apk add curl`）；
- **仓库地址不可达**：确认 `https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh` 能正常访问（浏览器打开看是否为 404；仓库未公开或地址拼错会返回 404）；
- **分支名不一致**：脚本默认从 **main 分支**下载仓库 tarball；若仓库默认分支是 `master` 等，请修改 `install.sh` 中 `fetch_remote_source` 的 tarball 地址分支名后再推送到 GitHub（最简单是让仓库保留 `main` 分支）。`GITHUB_RAW_URL` 环境变量只能帮助推导 owner/repo，**不能**改变下载用的分支名；
- **网络不通**：`curl -I https://raw.githubusercontent.com` 测试连通性；国内 VPS 访问 GitHub 不稳时可走代理，或改用本地安装方式（上传项目目录后 `sudo bash install.sh`）。

**12. 卸载后如何确认没有残留？**

```bash
systemctl status vpsmon        # 应提示 unit not found / could not be found
ls /opt/vpsmon                 # 应提示 No such file or directory
id vpsmon                      # 应提示 no such user
ls /var/lib/vpsmon             # 数据目录默认保留；如已确认删除则同样不存在
```

**13. 为什么卸载用 `sudo bash uninstall.sh` 而不是直接执行？**

卸载脚本需要 root 权限删除系统目录与系统用户，且 `sudo bash uninstall.sh` 不依赖脚本执行位、兼容性更好（即使从 `/opt/vpsmon/` 远程/本地任意位置调用均可）；脚本开头也会做 root 检查并给出 `sudo bash uninstall.sh` 提示。

---

## 统计口径与设计说明

- **只存累计计数**：样本表存内核累计收发字节数（`rx_bytes`/`tx_bytes`），不存速率与区间流量；一切由查询时相邻样本正增量推导（SPEC §8.1）。
- **免疫重启/重置**：进程重启后仍从内核续读累计值；计数器回退产生的负增量被忽略。
- **单写多读**：采集线程是唯一写库者，API 只读；SQLite WAL 模式避免锁争用。
- **目录结构**：

```
vpsmon/
├── install.sh / uninstall.sh   # 一键安装 / 卸载脚本（Linux systemd 分支 + OpenWrt opkg/procd/uci 分支；端口交互输入、token 自动生成、防火墙自动放行与撤销）
├── requirements.txt            # flask==3.1.3, psutil==7.2.2（精确 pin；OpenWrt 分支不安装）
├── vpsmon.service              # systemd 单元参考模板（ProtectSystem=strict + 最小权限；install.sh 按版本分档生成）
├── docs/SECURITY.md            # 安全审计与加固方案（威胁模型、风险清单、验收清单、OpenWrt §4.12）
├── docs/SPEC.md                # 技术规格说明（API 契约、算法、部署细节、OpenWrt §13）
└── vpsmon/
    ├── app.py                  # 入口：配置→存储→采集线程→双后端自动选择（Flask / stdlib）；安全响应头/Host 校验/日志脱敏
    ├── config.py               # 配置加载/校验/回退（含 bind/allow_ips/rate_limit/TLS 等安全字段；探测含 /etc/vpsmon/config.json）
    ├── collector.py            # 采集线程：psutil 采样→写库（缺失自动切 /proc）；网卡自动选择
    ├── procmetrics.py          # /proc 采集后端（OpenWrt 纯标准库：net_dev/cpu/meminfo/statvfs/uptime）
    ├── security.py             # 框架无关安全原语（鉴权/限流/白名单/安全头/Host 校验，双后端复用）
    ├── api.py                  # 6 端点纯处理器 + Flask 蓝图薄适配（恒定时间鉴权/限流/白名单/参数校验）
    ├── stdserver.py            # 纯标准库 HTTP 服务器（OpenWrt 后端：ThreadingHTTPServer + 路由/安全门/静态文件/TLS）
    ├── storage.py              # SQLite：建表/WAL（失败自动回退 DELETE）/正增量聚合查询
    └── static/                 # 仪表盘前端（ECharts 本地化，无 CDN 兜底）
```

- **自检**（开发验证）：`python -m vpsmon.storage`、`python -m vpsmon.collector --self-test`、`python -m vpsmon.api`（需 Flask）、`python -m vpsmon.config`、`python -m vpsmon.app --selftest`；stdlib 路径（无 Flask/psutil，模拟 OpenWrt）：`python -m vpsmon.procmetrics --self-test`、`python -m vpsmon.security --self-test`、`python -m vpsmon.stdserver --self-test`（有 Flask 时含双后端逐字段契约对比）、`python vpsmon/app.py --selftest`（直接脚本执行，T1 兼容层）。install.sh 提供 `bash install.sh --selftest`（systemd 单元分档 + OpenWrt 分支静态断言）。

---

## License

本项目为团队内部交付（vpsmon），仅供学习与自用部署。
