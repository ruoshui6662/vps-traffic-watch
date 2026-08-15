#!/usr/bin/env bash
# =============================================================================
# VPS 流量统计监控系统 — 一键安装 / 卸载脚本
#
# 用法:
#   sudo bash install.sh                                      # 交互安装（提示输入端口与 token）
#   sudo bash install.sh --port 9090 --interval 30 --token "mytoken" --iface eth0
#   sudo bash install.sh uninstall                            # 卸载（交互确认是否删除数据）
#   sudo bash install.sh uninstall --keep-data                # 卸载并保留 /var/lib/vpsmon 数据
#
# 远程一键安装（仓库: github.com/ruoshui6662/vps-traffic-watch）:
#   非交互管道模式（stdin 非终端）必须显式指定监听端口，否则报错退出:
#   curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh | sudo bash -s -- --port 9090
#   交互模式（bash -c 形式，stdin 仍是终端）会提示输入端口与 token:
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh)"
#   也可用环境变量（优先级低于同名参数）: VPSMON_PORT=9090 VPSMON_TOKEN=xxx
#
# 安装流程: root 检查 → 端口解析(交互输入/--port/VPSMON_PORT) → token 解析 →
#           源码来源检测(本地/GitHub远程) → 发行版检测 → 系统依赖 → 系统用户 →
#           复制程序 → venv 依赖 → 数据目录/配置 → systemd 服务 → 启动 → curl 自检 →
#           防火墙放行(交互确认) → 输出访问地址与安全提示
# =============================================================================
set -euo pipefail

# ---------- 常量 ----------
APP_DIR="/opt/vpsmon"              # 程序目录（vpsmon 包 + requirements.txt + venv）
DATA_DIR="/var/lib/vpsmon"         # 数据目录（config.json + vpsmon.db + .firewall-rule）
SERVICE_NAME="vpsmon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_FILE="${DATA_DIR}/config.json"
FIREWALL_MARKER="${DATA_DIR}/.firewall-rule"   # 记录安装时自动放行的防火墙规则

# ---------- 默认参数 ----------
PORT=""            # 监听端口（不再静默默认 8080；交互输入或 --port/VPSMON_PORT 指定）
PORT_SET=0         # 1 = 端口已由 --port 显式提供
INTERVAL="60"
TOKEN=""           # 访问令牌（默认自动生成强随机；--token "" 显式不鉴权）
TOKEN_SET=0        # 1 = token 已由 --token 显式提供（含空串 = 显式不鉴权）
TOKEN_AUTO=0       # 1 = 非交互模式待自动生成 token
IFACE=""
KEEP_DATA=0
MODE="install"

# ---------- 脚本所在目录（安装文件 vpsmon/、requirements.txt、vpsmon.service 的来源） ----------
# 远程执行（curl ... | bash）时 BASH_SOURCE[0] 为空或不可用，回退到当前目录；
# 真正的源码根目录由 detect_source / fetch_remote_source 在安装流程中确定。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || printf '%s' "$PWD")"

# ---------- GitHub 仓库配置（远程一键安装） ----------
# 默认仓库: https://github.com/ruoshui6662/vps-traffic-watch（main 分支）。
# 远程一行安装（非交互管道模式必须显式指定监听端口）:
#   curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh | sudo bash -s -- --port 9090
#   # 或（交互模式，会提示输入端口与 token）
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/install.sh)"
# Fork 或自建仓库时可用环境变量覆盖（优先级最高，无需修改脚本）:
#   REPO_OWNER=myuser REPO_NAME=myrepo sudo bash -c "$(curl -fsSL <上面的地址>)"
# 供应链校验（可选）: 设置 VPSMON_EXPECTED_SHA256=<发布方公布的 tarball 校验和>，
# 下载后会先做 sha256sum 比对，不匹配立即退出。详见 docs/SECURITY.md §4.11。
# 注意: 默认下载 main 分支；若仓库默认分支为 master 等，请同步修改
#       fetch_remote_source 中 tarball 地址的分支名。
REPO_OWNER="${REPO_OWNER:-ruoshui6662}"       # GitHub 用户名/组织名（默认本仓库）
REPO_NAME="${REPO_NAME:-vps-traffic-watch}"   # 仓库名（默认本仓库）
GITHUB_RAW_URL="${GITHUB_RAW_URL:-}"          # 可选: install.sh 的 raw 地址，设置后自动推导 owner/repo

# ---------- 彩色输出 ----------
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  C_GREEN="$(tput setaf 2)"
  C_YELLOW="$(tput setaf 3)"
  C_RED="$(tput setaf 1)"
  C_BOLD="$(tput bold)"
  C_RESET="$(tput sgr0)"
else
  C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""; C_RESET=""
fi

info() { printf '%s\n' "${C_GREEN}[*]${C_RESET} $*"; }
warn() { printf '%s\n' "${C_YELLOW}[!]${C_RESET} $*"; }
err()  { printf '%s\n' "${C_RED}[x]${C_RESET} $*" >&2; }

usage() {
  cat <<'EOF'
用法: sudo bash install.sh [选项]
      sudo bash install.sh uninstall [--keep-data]

选项:
  --port <端口>      监听端口（1-65535）。交互安装时提示输入；非交互/管道模式
                     必须提供 --port 或环境变量 VPSMON_PORT，否则报错退出
  --interval <秒>    采集间隔（默认 60，下限 5）
  --token <字符串>   访问令牌。默认自动生成强随机（非交互）；--token "" 显式不鉴权；
                     交互安装时提示输入（可留空 = 不鉴权，公网部署存在风险）
  --iface <网卡>     统计网卡名（默认空 = 自动选择流量最大的网卡）
  --keep-data        卸载时保留 /var/lib/vpsmon 数据目录
  -h, --help         显示本帮助

远程安装（项目托管到 GitHub 后，非交互管道模式必须指定端口）:
  curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh | sudo bash -s -- --port 9090
  # 或交互式（stdin 为终端时提示输入端口与 token）:
  sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh)"
EOF
}

# ---------- 参数解析 ----------
while [ $# -gt 0 ]; do
  case "$1" in
    uninstall)     MODE="uninstall"; shift ;;
    --port)        [ $# -ge 2 ] || { err "--port 缺少参数值"; usage; exit 1; }; PORT="$2"; PORT_SET=1; shift 2 ;;
    --port=*)      PORT="${1#*=}"; PORT_SET=1; shift ;;
    --interval)    [ $# -ge 2 ] || { err "--interval 缺少参数值"; usage; exit 1; }; INTERVAL="$2"; shift 2 ;;
    --interval=*)  INTERVAL="${1#*=}"; shift ;;
    --token)       [ $# -ge 2 ] || { err "--token 缺少参数值"; usage; exit 1; }; TOKEN="$2"; TOKEN_SET=1; shift 2 ;;
    --token=*)     TOKEN="${1#*=}"; TOKEN_SET=1; shift ;;
    --iface)       [ $# -ge 2 ] || { err "--iface 缺少参数值"; usage; exit 1; }; IFACE="$2"; shift 2 ;;
    --iface=*)     IFACE="${1#*=}"; shift ;;
    --keep-data)   KEEP_DATA=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) err "未知参数: $1"; usage; exit 1 ;;
  esac
done

# 环境变量兜底（优先级低于同名参数）: VPSMON_PORT / VPSMON_TOKEN
if [ "$PORT_SET" = "0" ] && [ -n "${VPSMON_PORT:-}" ]; then
  PORT="$VPSMON_PORT"
  PORT_SET=1
fi
if [ "$TOKEN_SET" = "0" ] && [ -n "${VPSMON_TOKEN:-}" ]; then
  TOKEN="$VPSMON_TOKEN"
  TOKEN_SET=1
fi

# ---------- 校验 ----------
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "需要 root 权限，请使用: sudo bash install.sh"
    exit 1
  fi
}

is_valid_port() {
  # 纯数字、最多 5 位且 1-65535；空串/非数字/越界均非法。
  # 用 10# 强制十进制，避免前导零被当作八进制（如 080、0080）。
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "${#1}" -le 5 ] || return 1
  local n=$((10#$1))
  [ "$n" -ge 1 ] && [ "$n" -le 65535 ]
}

validate_interval() {
  if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 5 ] || [ "$INTERVAL" -gt 86400 ]; then
    err "采集间隔无效: $INTERVAL（应为 5-86400 的整数）"
    exit 1
  fi
}

# ---------- 端口解析（SECURITY.md §4.10-A：不再静默默认 8080） ----------
# 优先级: --port 参数 > VPSMON_PORT 环境变量 > 交互输入 > 非交互报错退出
resolve_port() {
  if [ "$PORT_SET" = "1" ]; then
    if ! is_valid_port "$PORT"; then
      err "端口无效: '$PORT'（应为 1-65535 的整数）"
      exit 1
    fi
    info "监听端口: $PORT"
    return 0
  fi

  if [ -t 0 ]; then
    # 交互模式（stdin 是终端）: 提示输入，非法重试（最多 3 次）
    local attempts=0
    while :; do
      printf '%s' "请输入监听端口（1-65535）：" >&2
      read -r PORT || true
      if is_valid_port "$PORT"; then
        info "监听端口: $PORT"
        return 0
      fi
      attempts=$((attempts + 1))
      if [ "$attempts" -ge 3 ]; then
        err "端口输入非法次数过多（3/3），已退出。"
        err "请重新运行，或使用: sudo bash install.sh --port <端口>"
        exit 1
      fi
      err "端口无效: '$PORT'（应为 1-65535 的整数），剩余重试机会: $((3 - attempts))"
    done
  fi

  # 非交互/管道模式（stdin 非终端）: 必须显式提供 --port 或 VPSMON_PORT，禁止回退默认值
  err "非交互模式（stdin 非终端）必须显式指定监听端口，不能回退默认值！"
  err "请使用 --port <端口> 或环境变量 VPSMON_PORT，例如:"
  err "  本地安装:  sudo bash install.sh --port 9090"
  err "  远程安装:  curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh | sudo bash -s -- --port 9090"
  err "  环境变量:  VPSMON_PORT=9090 sudo bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh)\""
  exit 1
}

# ---------- token 解析（SECURITY.md §4.10-B：默认自动生成强随机） ----------
# 交互输入阶段: 交互模式提示用户输入（可留空=不鉴权，显著警告）；
# 非交互模式未给 token 时置 TOKEN_AUTO=1，依赖安装完成后自动生成（保证 openssl/python3 可用）。
resolve_token_prompt() {
  if [ "$TOKEN_SET" = "1" ]; then
    # --token / VPSMON_TOKEN 已显式提供（含空串 = 显式不鉴权）
    if [ -z "$TOKEN" ]; then
      warn "已按显式指定不设置 token（不鉴权）——任何人均可读取全部监控数据！"
    elif [ "${#TOKEN}" -lt 8 ]; then
      warn "警告: token 长度仅 ${#TOKEN} 字符（建议 >= 8 字符，推荐使用自动生成的强随机 token）"
    fi
    return 0
  fi

  if [ -t 0 ]; then
    local ans=""
    printf '%s' "请输入访问令牌（直接回车 = 不开启鉴权，公网部署存在风险）：" >&2
    read -r ans || true
    TOKEN="$ans"
    if [ -n "$TOKEN" ] && [ "${#TOKEN}" -lt 8 ]; then
      warn "警告: token 长度仅 ${#TOKEN} 字符（建议 >= 8 字符，推荐使用自动生成的强随机 token）"
    fi
    if [ -z "$TOKEN" ]; then
      warn "警告: 未设置 token —— 任何人均可读取全部监控数据！强烈建议设置 token。"
    fi
  else
    TOKEN_AUTO=1
  fi
}

# 自动生成强随机 token（128 bit 熵）：openssl → /dev/urandom+od → python3 secrets
generate_token() {
  local t=""
  if command -v openssl >/dev/null 2>&1; then
    t="$(openssl rand -hex 16 2>/dev/null || true)"
  fi
  if [ -z "$t" ] && command -v od >/dev/null 2>&1 && [ -r /dev/urandom ]; then
    t="$(od -An -N32 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' || true)"
  fi
  if [ -z "$t" ] && command -v python3 >/dev/null 2>&1; then
    t="$(python3 -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null || true)"
  fi
  if [ -z "$t" ]; then
    err "无法生成强随机 token（openssl/od/python3 均不可用），请使用 --token 显式指定"
    exit 1
  fi
  printf '%s' "$t"
}

resolve_token_generate() {
  if [ "$TOKEN_AUTO" = "1" ]; then
    TOKEN="$(generate_token)"
    info "已自动生成强随机访问令牌（128 bit 熵）"
  fi
}

# ---------- 发行版检测 ----------
detect_distro() {
  if [ ! -r /etc/os-release ]; then
    err "未找到 /etc/os-release，无法识别发行版"
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  case "$ID" in
    debian|ubuntu)
      PKG_MGR="apt"
      PKG_PY="python3 python3-venv python3-pip curl"
      ;;
    centos|rhel|rocky|alma|fedora)
      if command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
      else
        PKG_MGR="yum"
      fi
      PKG_PY="python3 python3-pip curl"
      ;;
    alpine)
      PKG_MGR="apk"
      PKG_PY="python3 py3-pip curl"
      ;;
    *)
      err "不支持的发行版: $ID（当前支持 apt/dnf/yum/apk）"
      err "请手动安装 python3 与 pip 后重试。"
      exit 1
      ;;
  esac
  info "检测到发行版: $ID，包管理器: $PKG_MGR"
}

# ---------- 安装系统依赖 ----------
install_system_deps() {
  info "安装系统依赖: $PKG_PY"
  case "$PKG_MGR" in
    apt) apt-get update -y && apt-get install -y $PKG_PY ;;
    dnf) dnf install -y $PKG_PY ;;
    yum) yum install -y $PKG_PY ;;
    apk) apk add --no-cache $PKG_PY ;;
  esac
  if ! command -v python3 >/dev/null 2>&1; then
    err "未找到 python3，请检查系统依赖安装是否成功"
    exit 1
  fi
  if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
    err "python3 版本过低（需要 >= 3.8）"
    exit 1
  fi
}

# ---------- 创建系统用户 ----------
create_user() {
  if id vpsmon >/dev/null 2>&1; then
    info "系统用户 vpsmon 已存在，跳过创建"
    return
  fi
  if [ "$PKG_MGR" = "apk" ]; then
    adduser -S -D -H -h "$APP_DIR" -s /sbin/nologin vpsmon
  else
    useradd --system --no-create-home --home-dir "$APP_DIR" --shell /usr/sbin/nologin vpsmon
  fi
  info "已创建系统用户 vpsmon"
}

# ---------- 复制程序 ----------
copy_program() {
  if [ ! -d "$SCRIPT_DIR/vpsmon" ]; then
    err "未找到 $SCRIPT_DIR/vpsmon 包目录，请在项目根目录执行本脚本"
    exit 1
  fi
  if [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
    err "未找到 $SCRIPT_DIR/requirements.txt"
    exit 1
  fi
  info "复制程序到 $APP_DIR"
  mkdir -p "$APP_DIR"
  cp -r "$SCRIPT_DIR/vpsmon" "$APP_DIR/"
  cp "$SCRIPT_DIR/requirements.txt" "$APP_DIR/"
}

# ---------- 部署卸载脚本（与程序一同装入 /opt/vpsmon，供日后一键卸载） ----------
copy_uninstall_script() {
  if [ -f "$SCRIPT_DIR/uninstall.sh" ]; then
    install -m 755 "$SCRIPT_DIR/uninstall.sh" "$APP_DIR/uninstall.sh"
    info "已部署卸载脚本 $APP_DIR/uninstall.sh（日后可用: sudo bash $APP_DIR/uninstall.sh 一键卸载）"
  else
    warn "未找到 $SCRIPT_DIR/uninstall.sh，跳过部署卸载脚本"
  fi
}

# ---------- 创建虚拟环境并安装依赖 ----------
setup_venv() {
  info "创建虚拟环境 $APP_DIR/venv"
  if ! python3 -m venv "$APP_DIR/venv"; then
    if [ "$PKG_MGR" = "apk" ]; then
      err "venv 创建失败，Alpine 请先安装: apk add py3-virtualenv，然后重试"
    fi
    err "venv 创建失败"
    exit 1
  fi
  info "安装 Python 依赖: pip install -r requirements.txt"
  "$APP_DIR/venv/bin/pip" install --no-cache-dir -r "$APP_DIR/requirements.txt"
  # SECURITY.md §4.10-D: /opt/vpsmon 归 root:root，程序目录对 vpsmon 用户只读。
  # 去掉旧的 chown -R vpsmon:vpsmon（防止服务被攻破后改写程序目录持久化后门），
  # 仅做 "去掉其他用户写权限" 保底；运行期由 vpsmon.service 的 ProtectSystem=strict 强制只读。
  chmod -R o-w "$APP_DIR"
}

# ---------- 数据目录与默认配置 ----------
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

write_config() {
  info "生成配置 $CONFIG_FILE"
  mkdir -p "$DATA_DIR"
  chmod 700 "$DATA_DIR"
  chown vpsmon:vpsmon "$DATA_DIR"
  # SECURITY.md §4.10-D: 用 umask 077 子 shell 包裹写入，消除 644 中间窗口（M6）；
  # 落盘即 600，随后再显式 chown/chmod 兜底。
  (
    umask 077
    cat > "$CONFIG_FILE" <<EOF
{
  "port": $PORT,
  "interval": $INTERVAL,
  "token": "$(json_escape "$TOKEN")",
  "iface": "$(json_escape "$IFACE")"
}
EOF
  )
  chown vpsmon:vpsmon "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
}

# ---------- 安装 systemd 服务 ----------
install_service() {
  if [ ! -f "$SCRIPT_DIR/vpsmon.service" ]; then
    err "未找到 $SCRIPT_DIR/vpsmon.service"
    exit 1
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "未检测到 systemd（当前系统可能使用 OpenRC 等 init），跳过服务注册"
    return 1
  fi
  info "安装 systemd 服务 $SERVICE_FILE"
  install -m 644 "$SCRIPT_DIR/vpsmon.service" "$SERVICE_FILE"
  systemctl daemon-reload
}

# ---------- 启动并 curl 自检 ----------
start_and_check() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 1
  fi
  info "启动服务: systemctl enable --now $SERVICE_NAME"
  systemctl enable --now "$SERVICE_NAME"

  info "自检: curl http://127.0.0.1:${PORT}/api/status"
  local i
  for i in $(seq 1 10); do
    if [ -n "$TOKEN" ]; then
      if curl -fsS --max-time 3 -H "X-Token: $TOKEN" \
          "http://127.0.0.1:${PORT}/api/status" 2>/dev/null | grep -q '"ok": true'; then
        return 0
      fi
    else
      if curl -fsS --max-time 3 \
          "http://127.0.0.1:${PORT}/api/status" 2>/dev/null | grep -q '"ok": true'; then
        return 0
      fi
    fi
    sleep 1
  done
  err "自检失败，服务未正常响应，最近日志:"
  journalctl -u "$SERVICE_NAME" -n 50 --no-pager 2>/dev/null || true
  return 1
}

# ---------- 公网 IP 探测：curl ifconfig.me，失败则用 hostname -I 第一项 ----------
detect_public_ip() {
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip="$(curl -fsSL --max-time 8 ifconfig.me 2>/dev/null || true)"
  fi
  if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  # 过滤回环地址
  case "$ip" in
    127.*|::1|"") ip="" ;;
  esac
  printf '%s' "$ip"
}

# ---------- 防火墙自动放行（SECURITY.md §4.10-C: 交互确认 + 标记记录） ----------
# 检测 ufw/firewalld 启用状态 → 交互确认 → 放行 → 写入 /var/lib/vpsmon/.firewall-rule。
# 非交互模式默认只提示（安全优先，不自动放行）。
firewall_allow() {
  local fw=""

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; then
    fw="ufw"
  elif command -v firewall-cmd >/dev/null 2>&1 \
       && systemctl is-active firewalld 2>/dev/null | grep -q active; then
    fw="firewalld"
  fi

  if [ -z "$fw" ]; then
    echo
    warn "未检测到启用的 ufw/firewalld，若无法从外部访问，请到云厂商安全组放行 TCP $PORT 端口"
    return 0
  fi

  # 端口已放行则跳过
  if [ "$fw" = "ufw" ] && ufw status 2>/dev/null | grep -qE "(^|[[:space:]])${PORT}/tcp"; then
    info "ufw 已放行 ${PORT}/tcp，跳过"
    return 0
  fi
  if [ "$fw" = "firewalld" ] && firewall-cmd --query-port="${PORT}/tcp" >/dev/null 2>&1; then
    info "firewalld 已放行 ${PORT}/tcp，跳过"
    return 0
  fi

  # 非交互模式：只提示不自动放行（安全优先）
  if [ ! -t 0 ]; then
    echo
    warn "检测到 $fw 正在运行，但当前为非交互模式（stdin 非终端），不自动放行端口。"
    warn "如需外部访问，请手动执行放行:"
    if [ "$fw" = "ufw" ]; then
      warn "  sudo ufw allow ${PORT}/tcp"
    else
      warn "  sudo firewall-cmd --permanent --add-port=${PORT}/tcp && sudo firewall-cmd --reload"
    fi
    return 0
  fi

  # 交互确认
  echo
  local ans=""
  printf '检测到 %s 正在运行。是否放行 TCP 端口 %s？[y/N] ' "$fw" "$PORT"
  read -r ans || true
  case "$ans" in
    y|Y|yes|YES)
      ;;
    *)
      warn "已跳过防火墙放行（如需外部访问请手动放行）"
      return 0
      ;;
  esac

  # 执行放行并记录标记（供卸载时撤销）
  if [ "$fw" = "ufw" ]; then
    if ufw allow "${PORT}/tcp" comment 'vpsmon' 2>/dev/null; then
      printf 'ufw|%s\n' "$PORT" > "$FIREWALL_MARKER"
      chmod 600 "$FIREWALL_MARKER"
      info "已放行 ufw: ${PORT}/tcp（规则已记录到 $FIREWALL_MARKER）"
    else
      warn "ufw 放行失败，请手动执行: sudo ufw allow ${PORT}/tcp"
    fi
  else
    if firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 \
       && firewall-cmd --reload >/dev/null 2>&1; then
      printf 'firewalld|%s\n' "$PORT" > "$FIREWALL_MARKER"
      chmod 600 "$FIREWALL_MARKER"
      info "已放行 firewalld: ${PORT}/tcp（规则已记录到 $FIREWALL_MARKER）"
    else
      warn "firewalld 放行失败，请手动执行: sudo firewall-cmd --permanent --add-port=${PORT}/tcp && sudo firewall-cmd --reload"
    fi
  fi
}

# ---------- 卸载时撤销安装自动添加的防火墙规则（SECURITY.md §4.10-C/S3） ----------
# 读取标记文件 → 撤销对应规则 → 删除标记。标记文件缺失则不撤销（避免误删用户既有规则）。
firewall_revoke() {
  if [ ! -f "$FIREWALL_MARKER" ]; then
    info "未找到防火墙规则标记 $FIREWALL_MARKER，跳过撤销（避免误删用户既有规则）"
    return 0
  fi
  local fw="" port=""
  # 格式: ufw|<port> 或 firewalld|<port>
  IFS='|' read -r fw port < "$FIREWALL_MARKER" || true
  if [ -z "$fw" ] || [ -z "$port" ]; then
    warn "防火墙标记文件格式异常: $(cat "$FIREWALL_MARKER" 2>/dev/null || true)，请手动撤销对应规则"
    rm -f "$FIREWALL_MARKER"
    return 0
  fi
  case "$fw" in
    ufw)
      if command -v ufw >/dev/null 2>&1; then
        if ufw delete allow "${port}/tcp" 2>/dev/null; then
          info "已撤销 ufw 放行规则: ${port}/tcp"
        else
          warn "ufw 撤销失败（规则可能已被手动删除），请检查: ufw status"
        fi
      else
        warn "未找到 ufw 命令，无法自动撤销，请手动执行: sudo ufw delete allow ${port}/tcp"
      fi
      ;;
    firewalld)
      if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 \
           && firewall-cmd --reload >/dev/null 2>&1; then
          info "已撤销 firewalld 放行规则: ${port}/tcp"
        else
          warn "firewalld 撤销失败（规则可能已被手动删除），请检查: firewall-cmd --list-ports"
        fi
      else
        warn "未找到 firewall-cmd 命令，无法自动撤销，请手动执行: sudo firewall-cmd --permanent --remove-port=${port}/tcp && sudo firewall-cmd --reload"
      fi
      ;;
    *)
      warn "未知防火墙类型: $fw，请手动撤销端口 ${port}/tcp 的放行规则"
      ;;
  esac
  rm -f "$FIREWALL_MARKER"
  info "已删除防火墙规则标记 $FIREWALL_MARKER"
}

# ---------- 成功信息 ----------
print_success() {
  local pub_ip
  pub_ip="$(detect_public_ip)"
  echo
  echo "============================================================"
  echo "  ${C_BOLD}${C_GREEN}VPS 流量统计监控系统安装成功！${C_RESET}"
  echo "------------------------------------------------------------"
  if [ -n "$pub_ip" ]; then
    printf '  访问地址: %s%s%s\n' "${C_BOLD}${C_GREEN}" "http://${pub_ip}:${PORT}" "${C_RESET}"
  else
    warn "未能探测公网 IP，请用服务器 IP 访问:"
    printf '  访问地址: %s%s%s\n' "${C_BOLD}${C_GREEN}" "http://<服务器IP>:${PORT}" "${C_RESET}"
  fi
  if [ -n "$TOKEN" ]; then
    echo "  ----------------------------------------------------------"
    printf '  %s访问令牌: %s%s（仅本次显示，请立即妥善保存）\n' "${C_BOLD}" "$TOKEN" "${C_RESET}"
    echo "  浏览器访问页面时输入该令牌；API 调用请使用请求头: X-Token: <token>"
  else
    echo "  ----------------------------------------------------------"
    warn "  当前未设置 token（不鉴权）——任何人均可读取全部监控数据！"
  fi
  echo "------------------------------------------------------------"
  if [ -n "$TOKEN" ]; then
    echo "  本机测试: curl -H \"X-Token: $TOKEN\" http://127.0.0.1:${PORT}/api/status"
  else
    echo "  本机测试: curl http://127.0.0.1:${PORT}/api/status"
  fi
  echo "  服务管理: systemctl status $SERVICE_NAME | journalctl -u $SERVICE_NAME -f"
  echo "  一键卸载: sudo bash $APP_DIR/uninstall.sh"
  echo "============================================================"
  echo
  echo "${C_YELLOW}安全提示:${C_RESET}"
  echo "  1. 请勿公开分享 token 与访问地址（token 是 /api/* 的唯一访问凭据）"
  echo "  2. 建议在防火墙/云安全组仅放行你的来源 IP，而非对全网开放"
  echo "  3. 若忘记 token，可编辑 $CONFIG_FILE 后执行: systemctl restart vpsmon"
  echo "  4. token 请通过请求头 X-Token 传递，避免 URL 携带 token 泄露到访问日志"
}

# ---------- 卸载 ----------
do_uninstall() {
  require_root
  echo
  info "开始卸载 VPS 流量统计监控系统..."

  # 1. 停止并禁用服务（若存在）
  if [ -f "$SERVICE_FILE" ] || systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}"; then
    info "停止并禁用服务: systemctl disable --now $SERVICE_NAME"
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  fi

  # 2. 撤销安装时自动添加的防火墙规则（在删除数据目录之前，标记文件尚存在）
  firewall_revoke

  # 3. 删除 systemd 单元
  if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    info "已删除 $SERVICE_FILE"
  fi

  # 4. 删除程序目录
  if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
    info "已删除 $APP_DIR"
  fi

  # 5. 数据目录：--keep-data 保留；否则交互确认（默认保留）
  if [ "$KEEP_DATA" = "1" ]; then
    warn "已指定 --keep-data，保留数据目录 $DATA_DIR（含 config.json 与 vpsmon.db）"
  elif [ -d "$DATA_DIR" ]; then
    local ans=""
    printf '%s' "是否同时删除数据目录 $DATA_DIR（含历史数据与配置）？[y/N] "
    read -r ans || true
    case "$ans" in
      y|Y|yes|YES)
        rm -rf "$DATA_DIR"
        info "已删除 $DATA_DIR"
        ;;
      *)
        warn "保留数据目录 $DATA_DIR"
        ;;
    esac
  fi

  # 6. 删除系统用户
  if id vpsmon >/dev/null 2>&1; then
    if userdel vpsmon 2>/dev/null; then
      info "已删除系统用户 vpsmon"
    else
      warn "删除用户 vpsmon 失败（可能仍有进程占用），可稍后手动执行: userdel vpsmon"
    fi
  fi

  echo
  info "卸载完成。"
}

# ---------- 源码来源检测: 本地目录 or GitHub 远程下载 ----------
# 本地模式: 脚本同目录存在 vpsmon/ 等安装文件（BASH_SOURCE[0] 可用的常规执行）。
# 远程模式: 经 stdin 管道执行（BASH_SOURCE[0] 为空，如 curl ... | sudo bash），
#           或同目录缺少安装文件时，自动从 GitHub 下载仓库 tarball 后继续安装。
SOURCE_MODE="local"

detect_source() {
  if [ -n "${BASH_SOURCE[0]:-}" ] && [ -d "$SCRIPT_DIR/vpsmon" ] \
     && [ -f "$SCRIPT_DIR/requirements.txt" ] && [ -f "$SCRIPT_DIR/vpsmon.service" ]; then
    SOURCE_MODE="local"
    info "本地模式: 使用 $SCRIPT_DIR 目录下的源码安装"
  else
    SOURCE_MODE="remote"
    info "远程模式: 将从 GitHub 下载仓库源码后安装"
  fi
}

fetch_remote_source() {
  # 未直接给出 owner/repo 时，尝试从 GITHUB_RAW_URL 推导（形如
  # https://raw.githubusercontent.com/<owner>/<repo>/<branch>/install.sh）
  if [ -z "$REPO_OWNER" ] || [ -z "$REPO_NAME" ]; then
    if [ -n "$GITHUB_RAW_URL" ]; then
      local raw_path="${GITHUB_RAW_URL#*github.com/}"
      REPO_OWNER="${raw_path%%/*}"
      REPO_NAME="${raw_path#*/}"
      REPO_NAME="${REPO_NAME%%/*}"
      info "已从 GITHUB_RAW_URL 推导仓库: $REPO_OWNER/$REPO_NAME"
    fi
  fi
  if [ -z "$REPO_OWNER" ] || [ -z "$REPO_NAME" ]; then
    err "远程安装缺少 GitHub 仓库信息。"
    err "请先将项目托管到 GitHub，然后在 install.sh 头部设置 REPO_OWNER/REPO_NAME"
    err "（或用环境变量覆盖: REPO_OWNER=xx REPO_NAME=yy），再重新执行远程安装。"
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    err "未找到 curl，无法下载远程源码，请先安装 curl 后重试。"
    exit 1
  fi
  if ! command -v tar >/dev/null 2>&1; then
    err "未找到 tar，无法解压源码包，请先安装 tar 后重试。"
    exit 1
  fi

  local tarball_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/main.tar.gz"
  REMOTE_TMP="$(mktemp -d)" || { err "创建临时目录失败"; exit 1; }
  trap 'rm -rf "$REMOTE_TMP"' EXIT

  info "下载仓库源码: $tarball_url"
  if ! curl -fsSL --max-time 120 -o "$REMOTE_TMP/repo.tar.gz" "$tarball_url"; then
    err "下载失败，请检查仓库地址、分支名与网络连通性。"
    err "也可改用本地安装: git clone https://github.com/$REPO_OWNER/$REPO_NAME.git 后进入目录执行 sudo bash install.sh"
    exit 1
  fi

  # SECURITY.md §4.11（H6）: 可选供应链完整性校验。
  # 设置 VPSMON_EXPECTED_SHA256=<发布方公布的 tarball 校验和> 时，
  # 下载后先 sha256sum 比对，不匹配立即退出（提示供应链风险）。
  if [ -n "${VPSMON_EXPECTED_SHA256:-}" ]; then
    if ! command -v sha256sum >/dev/null 2>&1; then
      err "已设置 VPSMON_EXPECTED_SHA256，但系统缺少 sha256sum 命令，无法校验"
      exit 1
    fi
    info "校验 tarball SHA256（VPSMON_EXPECTED_SHA256）..."
    local actual
    actual="$(sha256sum "$REMOTE_TMP/repo.tar.gz" | awk '{print $1}')"
    if [ "$actual" != "$VPSMON_EXPECTED_SHA256" ]; then
      err "SHA256 校验失败，下载内容可能被篡改（供应链风险）！"
      err "  期望: $VPSMON_EXPECTED_SHA256"
      err "  实际: $actual"
      err "请确认 VPSMON_EXPECTED_SHA256 与仓库地址无误后重试。"
      exit 1
    fi
    info "SHA256 校验通过。"
  fi

  info "解压源码包..."
  tar -xzf "$REMOTE_TMP/repo.tar.gz" -C "$REMOTE_TMP"

  # GitHub tarball 顶层目录形如 <repo>-<commit>，取第一个目录作为源码根
  local extracted_dir=""
  for d in "$REMOTE_TMP"/*/; do
    if [ -d "$d" ]; then
      extracted_dir="$d"
      break
    fi
  done
  if [ -z "$extracted_dir" ]; then
    err "解压失败: 压缩包中未找到源码目录"
    exit 1
  fi
  SCRIPT_DIR="${extracted_dir%/}"

  # 校验下载内容完整性
  if [ ! -d "$SCRIPT_DIR/vpsmon" ] || [ ! -f "$SCRIPT_DIR/requirements.txt" ] || [ ! -f "$SCRIPT_DIR/vpsmon.service" ]; then
    err "下载内容不完整: 仓库中缺少 vpsmon/、requirements.txt 或 vpsmon.service"
    err "请确认 $REPO_OWNER/$REPO_NAME 的 main 分支包含完整项目源码。"
    exit 1
  fi
  info "源码就绪: $SCRIPT_DIR"
}

# ---------- 主流程 ----------
main() {
  if [ "$MODE" = "uninstall" ]; then
    do_uninstall
    exit 0
  fi

  require_root
  resolve_port        # 端口：--port/VPSMON_PORT > 交互输入 > 非交互报错
  validate_interval
  resolve_token_prompt
  detect_source
  if [ "$SOURCE_MODE" = "remote" ]; then
    fetch_remote_source
  fi
  detect_distro
  install_system_deps
  resolve_token_generate   # 非交互未给 token 时自动生成（依赖安装完成后，保证 openssl/python3 可用）
  create_user
  copy_program
  copy_uninstall_script
  setup_venv
  write_config
  install_service || true

  if ! start_and_check; then
    err "安装未完全成功。"
    if ! command -v systemctl >/dev/null 2>&1; then
      err "本系统无 systemd，可手动启动验证: $APP_DIR/venv/bin/python $APP_DIR/vpsmon/app.py --config $CONFIG_FILE"
      err "如需开机自启，请自行配置 OpenRC/rc.local 等。"
    else
      err "请查看日志排障: journalctl -u $SERVICE_NAME -n 50 --no-pager"
    fi
    exit 1
  fi

  firewall_allow
  print_success
}

main "$@"
