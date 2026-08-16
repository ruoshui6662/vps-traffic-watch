#!/usr/bin/env bash
# =============================================================================
# VPS 流量统计监控系统 — 一键安装 / 卸载脚本
#
# 用法:
#   sudo bash install.sh                                      # 交互安装（提示输入端口与 token）
#   sudo bash install.sh --port 9090 --interval 30 --token "mytoken" --iface eth0
#   sudo bash install.sh uninstall                            # 卸载（交互确认是否删除数据）
#   sudo bash install.sh uninstall --keep-data                # 卸载并保留 /var/lib/vpsmon 数据
#   sudo bash install.sh --selftest                           # 自检 systemd 单元分档生成（无需 root）
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
#           复制程序 → venv 依赖 → 数据目录/配置 → systemd 服务（单元按目标版本分档生成，
#           见 generate_service_unit_for / --selftest）→ 启动 → curl 自检 →
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
SYSTEMD_VERSION="0"   # 检测到的 systemd 主版本（安装时由 detect_systemd_version 填充）

# ---------- OpenWrt 平台常量（SPEC §13.3.3: /var 为 tmpfs 重启清空，数据/配置放 overlay 的 /etc/vpsmon） ----------
OPENWRT_DATA_DIR="/etc/vpsmon"
OPENWRT_CONFIG_FILE="${OPENWRT_DATA_DIR}/config.json"
OPENWRT_INIT_FILE="/etc/init.d/vpsmon"
OPENWRT_FIREWALL_MARKER="${OPENWRT_DATA_DIR}/.firewall-rule"
OPENWRT_PLATFORM=0   # 1 = OpenWrt/ImmortalWrt 平台（detect_distro 时置位；包管理器 opkg 或 apk 均可能）

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
SELFTEST=0

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
  --selftest         自检 systemd 单元分档生成逻辑（无需 root）
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
    --selftest)    SELFTEST=1; shift ;;
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

# ---------- OpenWrt 平台判定（安装/卸载共用；SPEC §13.3.1） ----------
# 命中任一即视为 OpenWrt/ImmortalWrt: /etc/openwrt_release 存在 / command -v opkg /
# os-release 的 ID 或 ID_LIKE 含 openwrt 或 immortalwrt。
# 注意: 新版 OpenWrt/ImmortalWrt（24.10+）包管理器已从 opkg 换成 apk，此处不能依赖 opkg 命令存在。
is_openwrt() {
  if [ -f /etc/openwrt_release ] || command -v opkg >/dev/null 2>&1; then
    return 0
  fi
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "$ID:$ID_LIKE" in
      *openwrt*) return 0 ;;
      *immortalwrt*) return 0 ;;
    esac
  fi
  return 1
}

# ---------- 发行版检测 ----------
detect_distro() {
  if [ ! -r /etc/os-release ]; then
    if is_openwrt; then
      OPENWRT_PLATFORM=1
      if command -v opkg >/dev/null 2>&1; then
        PKG_MGR="opkg"
        info "检测到发行版: openwrt（无 os-release，由 opkg 判定），包管理器: opkg"
      elif command -v apk >/dev/null 2>&1; then
        PKG_MGR="apk"
        info "检测到发行版: openwrt（无 os-release，由 apk 判定），包管理器: apk"
      else
        err "检测到 OpenWrt 平台，但未找到 opkg 或 apk 包管理器，无法安装依赖"
        exit 1
      fi
      PKG_PY="python3 curl ca-bundle"
      return 0
    fi
    err "未找到 /etc/os-release，无法识别发行版"
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  if is_openwrt; then
    OPENWRT_PLATFORM=1
    PKG_PY="python3 curl ca-bundle"   # python3 = 完整包（python3-light 缺 sqlite3/http.server）
    if command -v opkg >/dev/null 2>&1; then
      PKG_MGR="opkg"
      info "检测到发行版: openwrt，包管理器: opkg"
    elif command -v apk >/dev/null 2>&1; then
      PKG_MGR="apk"
      info "检测到发行版: openwrt（apk 系，ImmortalWrt/OpenWrt 24.10+），包管理器: apk"
    else
      err "检测到 OpenWrt 平台（ID=$ID），但未找到 opkg 或 apk 包管理器，无法安装依赖"
      exit 1
    fi
    return 0
  fi
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
      err "不支持的发行版: $ID（当前支持 apt/dnf/yum/apk/opkg）"
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
    apk)
      if [ "$OPENWRT_PLATFORM" = "1" ]; then
        # OpenWrt/ImmortalWrt 24.10+（apk-tools 系）: 先 update 再 add（--no-cache 为 Alpine 语义，OpenWrt apk 不保证支持）
        local free_kb
        free_kb="$(df -P / 2>/dev/null | awk 'NR==2 {print $4}')"
        if [ -n "$free_kb" ] && [ "$free_kb" -lt 16384 ] 2>/dev/null; then
          err "可用 Flash 空间不足: $(df -h / 2>/dev/null | awk 'NR==2 {print $4}')（需 ≥ 16MB）"
          err "python3 完整包安装后占用 10-20MB+，请先清理 overlay 空间（apk del 无用包）后重试"
          exit 1
        fi
        info "存储空间检查通过: $(df -h / 2>/dev/null | awk 'NR==2 {print $4}') 可用（需 ≥ 16MB）"
        if ! apk update; then
          err "apk update 失败，请检查网络与软件源配置（/etc/apk/repositories.d 或 /etc/apk/repositories）"
          err "可手动执行: apk update && apk add $PKG_PY 后重试"
          exit 1
        fi
        if ! apk add $PKG_PY; then
          err "apk add $PKG_PY 失败，请检查网络与软件源后重试"
          exit 1
        fi
      else
        apk add --no-cache $PKG_PY
      fi
      ;;
    opkg)
      # OpenWrt（SPEC §13.3.2）: 小 Flash 设备先检查 overlay 可用空间（python3 完整包
      # 安装后 10-20MB+，文档要求 ≥16MB 可用），不足时明确报错不静默。
      local free_kb
      free_kb="$(df -P / 2>/dev/null | awk 'NR==2 {print $4}')"
      if [ -n "$free_kb" ] && [ "$free_kb" -lt 16384 ] 2>/dev/null; then
        err "可用 Flash 空间不足: $(df -h / 2>/dev/null | awk 'NR==2 {print $4}')（需 ≥ 16MB）"
        err "python3 完整包安装后占用 10-20MB+，请先清理 overlay 空间（opkg remove 无用包）后重试"
        exit 1
      fi
      info "存储空间检查通过: $(df -h / 2>/dev/null | awk 'NR==2 {print $4}') 可用（需 ≥ 16MB）"
      if ! opkg update; then
        err "opkg update 失败，请检查网络与软件源配置（/etc/opkg/distfeeds.conf）"
        err "可手动执行: opkg update && opkg install $PKG_PY 后重试"
        exit 1
      fi
      if ! opkg install $PKG_PY; then
        err "opkg install $PKG_PY 失败，请检查网络与软件源后重试"
        exit 1
      fi
      ;;
  esac
  if ! command -v python3 >/dev/null 2>&1; then
    err "未找到 python3，请检查系统依赖安装是否成功"
    exit 1
  fi
  if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
    err "python3 版本过低（需要 >= 3.8）"
    exit 1
  fi
  if [ "$OPENWRT_PLATFORM" = "1" ]; then
    # OpenWrt: 必须用完整包 python3（python3-light 缺 sqlite3/http.server 等模块，启动即崩）
    if ! python3 -c 'import sqlite3, http.server, json, ssl, socketserver' 2>/dev/null; then
      err "检测到 python3 缺 sqlite3/http.server 等模块（可能误装了 python3-light），请安装完整包:"
      err "  opkg install python3     （opkg 系）"
      err "  apk add python3          （apk 系，ImmortalWrt/OpenWrt 24.10+）"
      exit 1
    fi
    info "python3 模块校验通过（sqlite3/http.server/json/ssl/socketserver）"
  fi
}

# ---------- 创建系统用户 ----------
create_user() {
  if [ "$OPENWRT_PLATFORM" = "1" ]; then
    info "OpenWrt 平台不创建系统用户（无此惯例，服务以 root 运行，见 docs/SPEC.md §13.5）"
    return 0
  fi
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
  if [ "$OPENWRT_PLATFORM" != "1" ] && [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
    err "未找到 $SCRIPT_DIR/requirements.txt"
    exit 1
  fi
  info "复制程序到 $APP_DIR"
  mkdir -p "$APP_DIR"
  cp -r "$SCRIPT_DIR/vpsmon" "$APP_DIR/"
  if [ "$OPENWRT_PLATFORM" = "1" ]; then
    # OpenWrt（SPEC §13.3.3）: 仅复制 vpsmon/ 包，无 venv/pip/编译；requirements.txt 供 VPS 用
    info "OpenWrt 平台仅复制 vpsmon/ 包（纯标准库运行，无 pip 依赖）"
  else
    cp "$SCRIPT_DIR/requirements.txt" "$APP_DIR/"
  fi
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
  if [ "$OPENWRT_PLATFORM" = "1" ]; then
    info "OpenWrt 平台跳过 venv/pip（纯标准库运行，无编译依赖；程序目录 root:root 只读）"
    return 0
  fi
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
  local data_dir="$DATA_DIR" cfg_file="$CONFIG_FILE"
  if [ "$OPENWRT_PLATFORM" = "1" ]; then
    # OpenWrt（SPEC §13.3.3）: /var 常符号链接到 /tmp（tmpfs）重启清空，配置/数据库
    # 必须放 overlay 的 /etc/vpsmon（jffs2/ubifs/overlayfs），重启后保留。
    data_dir="$OPENWRT_DATA_DIR"
    cfg_file="$OPENWRT_CONFIG_FILE"
    info "OpenWrt 数据/配置目录: $data_dir（/etc 为 overlay，重启保留）"
  fi
  info "生成配置 $cfg_file"
  mkdir -p "$data_dir"
  chmod 700 "$data_dir"
  if [ "$OPENWRT_PLATFORM" != "1" ]; then
    chown vpsmon:vpsmon "$data_dir"
  fi
  # SECURITY.md §4.10-D: 用 umask 077 子 shell 包裹写入，消除 644 中间窗口（M6）；
  # 落盘即 600，随后再显式 chown/chmod 兜底。
  (
    umask 077
    cat > "$cfg_file" <<EOF
{
  "port": $PORT,
  "interval": $INTERVAL,
  "token": "$(json_escape "$TOKEN")",
  "iface": "$(json_escape "$IFACE")"
}
EOF
  )
  if [ "$OPENWRT_PLATFORM" != "1" ]; then
    chown vpsmon:vpsmon "$cfg_file"
  fi
  chmod 600 "$cfg_file"
}

# =============================================================================
# OpenWrt 分支（SPEC §13.3）: opkg 依赖 / procd 服务 / uci 防火墙 / 卸载。
# 与 systemd 路径完全隔离——本区块内不出现 systemd 系命令与其它包管理器命令。
# =============================================================================

# ---------- OpenWrt procd 服务（SPEC §13.3.5: 无 systemd，用 /etc/init.d rc.common + procd） ----------
openwrt_install_service() {
  info "生成 procd 服务 $OPENWRT_INIT_FILE（START=99/STOP=10）"
  cat > "${OPENWRT_INIT_FILE}.new" <<'EOF'
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
EOF
  install -m 755 "${OPENWRT_INIT_FILE}.new" "$OPENWRT_INIT_FILE"
  rm -f "${OPENWRT_INIT_FILE}.new"
  info "启用开机自启: /etc/init.d/vpsmon enable"
  "$OPENWRT_INIT_FILE" enable 2>/dev/null || warn "/etc/init.d/vpsmon enable 失败（可稍后手动执行）"
  info "启动服务: /etc/init.d/vpsmon start"
  if ! "$OPENWRT_INIT_FILE" start 2>/dev/null; then
    err "/etc/init.d/vpsmon start 失败，请查看日志: logread | grep vpsmon"
    return 1
  fi
  return 0
}

# ---------- OpenWrt curl 自检（与 systemd 版 start_and_check 等价；日志看 logread） ----------
openwrt_start_and_check() {
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
  logread 2>/dev/null | grep vpsmon | tail -n 30 || true
  return 1
}

# ---------- OpenWrt uci 防火墙放行（SPEC §13.3.6: 交互确认 + 查重 + 标记 uci|<段名>） ----------
openwrt_firewall_allow() {
  if ! command -v uci >/dev/null 2>&1 || [ ! -f /etc/config/firewall ]; then
    echo
    warn "未检测到 uci 防火墙（/etc/config/firewall 不存在），若无法从外部访问请手动放行 TCP $PORT 端口"
    return 0
  fi
  # 查重: 已有 name=vpsmon 规则则跳过（避免重复规则）
  if uci show firewall 2>/dev/null | grep -q "name='vpsmon'"; then
    info "uci 防火墙已有 vpsmon 规则，跳过"
    return 0
  fi
  # 非交互模式：只提示不自动放行（安全优先，与现有 ufw/firewalld 语义一致）
  if [ ! -t 0 ]; then
    echo
    warn "检测到 uci 防火墙，但当前为非交互模式（stdin 非终端），不自动放行端口。"
    warn "如需外部访问，请手动执行放行:"
    warn "  uci add firewall rule && uci set firewall.@rule[-1].name='vpsmon'"
    warn "  uci set firewall.@rule[-1].src='lan' && uci set firewall.@rule[-1].proto='tcp'"
    warn "  uci set firewall.@rule[-1].dest_port='${PORT}' && uci set firewall.@rule[-1].target='ACCEPT'"
    warn "  uci commit firewall && /etc/init.d/firewall reload"
    return 0
  fi
  # 交互确认
  echo
  local ans=""
  printf '检测到 uci 防火墙。是否放行 TCP 端口 %s（来源 lan）？[y/N] ' "$PORT"
  read -r ans || true
  case "$ans" in
    y|Y|yes|YES)
      ;;
    *)
      warn "已跳过防火墙放行（如需外部访问请手动放行）"
      return 0
      ;;
  esac
  # 执行放行并记录标记（段名精确撤销，供卸载时使用）
  local sec
  sec="$(uci add firewall rule 2>/dev/null || true)"
  if [ -z "$sec" ]; then
    warn "uci add firewall rule 失败，请手动放行 TCP $PORT 端口"
    return 0
  fi
  uci set firewall."${sec}".name='vpsmon'
  uci set firewall."${sec}".src='lan'
  uci set firewall."${sec}".proto='tcp'
  uci set firewall."${sec}".dest_port="$PORT"
  uci set firewall."${sec}".target='ACCEPT'
  if uci commit firewall 2>/dev/null && /etc/init.d/firewall reload 2>/dev/null; then
    printf 'uci|%s\n' "$sec" > "$OPENWRT_FIREWALL_MARKER"
    chmod 600 "$OPENWRT_FIREWALL_MARKER"
    info "已放行 uci 防火墙: TCP $PORT（规则段 $sec，已记录到 $OPENWRT_FIREWALL_MARKER）"
  else
    warn "uci 放行失败，请手动执行: uci add firewall rule 并设置 name=vpsmon/proto=tcp/dest_port=$PORT/target=ACCEPT"
  fi
}

# ---------- OpenWrt uci 防火墙撤销（SPEC §13.3.6/13.3.7: 按标记段名精确删除，标记缺失不撤销） ----------
openwrt_firewall_revoke() {
  if [ ! -f "$OPENWRT_FIREWALL_MARKER" ]; then
    info "未找到 uci 防火墙标记 $OPENWRT_FIREWALL_MARKER，跳过撤销（避免误删用户既有规则）"
    return 0
  fi
  local fw="" sec=""
  # 格式: uci|<段名>（如 uci|cfg0123ab）
  IFS='|' read -r fw sec < "$OPENWRT_FIREWALL_MARKER" || true
  if [ "$fw" != "uci" ] || [ -z "$sec" ]; then
    warn "uci 标记格式异常: $(cat "$OPENWRT_FIREWALL_MARKER" 2>/dev/null || true)，请手动检查: uci show firewall | grep vpsmon"
    rm -f "$OPENWRT_FIREWALL_MARKER"
    return 0
  fi
  # 段已不存在（可能被手动删除）→ 直接清标记
  if ! uci show firewall 2>/dev/null | grep -q "^firewall\.${sec}="; then
    info "uci 规则段 $sec 已不存在（可能已被手动删除），跳过撤销"
    rm -f "$OPENWRT_FIREWALL_MARKER"
    return 0
  fi
  # 双保险: 仅当该段 name=vpsmon 时才删除（避免误删用户既有规则）
  if uci get firewall."${sec}".name 2>/dev/null | grep -q vpsmon; then
    uci delete firewall."${sec}" 2>/dev/null
    if uci commit firewall 2>/dev/null && /etc/init.d/firewall reload 2>/dev/null; then
      info "已撤销 uci 防火墙规则段 $sec"
    else
      warn "uci 撤销提交失败，请手动检查: uci show firewall | grep vpsmon"
    fi
  else
    warn "uci 规则段 $sec 的 name 不是 vpsmon，跳过撤销（避免误删用户既有规则）"
  fi
  rm -f "$OPENWRT_FIREWALL_MARKER"
  info "已删除 uci 防火墙标记 $OPENWRT_FIREWALL_MARKER"
}

# ---------- OpenWrt 卸载分支（SPEC §13.3.7: 停服/disable → 撤销 uci → 删 init/程序/数据） ----------
openwrt_do_uninstall() {
  # 1. 停止并禁用服务（若存在）
  if [ -f "$OPENWRT_INIT_FILE" ]; then
    info "停止服务: /etc/init.d/vpsmon stop"
    "$OPENWRT_INIT_FILE" stop 2>/dev/null || true
    info "禁用开机自启: /etc/init.d/vpsmon disable"
    "$OPENWRT_INIT_FILE" disable 2>/dev/null || true
  fi
  # 2. 撤销 uci 防火墙规则（在删除数据目录之前，标记文件尚存在）
  openwrt_firewall_revoke
  # 3. 删除 init 脚本
  if [ -f "$OPENWRT_INIT_FILE" ]; then
    rm -f "$OPENWRT_INIT_FILE"
    info "已删除 $OPENWRT_INIT_FILE"
  fi
  # 4. 删除程序目录
  if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
    info "已删除 $APP_DIR"
  fi
  # 5. 数据目录 /etc/vpsmon: --keep-data 保留；否则交互确认（默认保留；非交互强制保留）
  if [ "$KEEP_DATA" = "1" ]; then
    warn "已指定 --keep-data，保留数据目录 $OPENWRT_DATA_DIR（含 config.json 与 vpsmon.db）"
  elif [ -d "$OPENWRT_DATA_DIR" ]; then
    if [ -t 0 ]; then
      local ans=""
      printf '%s' "是否同时删除数据目录 $OPENWRT_DATA_DIR（含历史数据与配置）？[y/N] "
      read -r ans || true
      case "$ans" in
        y|Y|yes|YES)
          rm -rf "$OPENWRT_DATA_DIR"
          info "已删除 $OPENWRT_DATA_DIR"
          ;;
        *)
          warn "保留数据目录 $OPENWRT_DATA_DIR"
          ;;
      esac
    else
      warn "检测到非交互执行（stdin 非终端），跳过删除确认，默认保留数据目录 $OPENWRT_DATA_DIR"
    fi
  fi
  # 6. 不卸载 python3/curl/ca-bundle 等 opkg/apk 包（可能被其他包依赖，卸载第三方包超出本应用职责）
  echo
  info "卸载完成。（未卸载 python3/curl/ca-bundle 等 opkg/apk 包——它们可能被其他包依赖）"
}

# ---------- OpenWrt 成功信息（SPEC §13.4: 管理用 /etc/init.d/vpsmon，日志用 logread） ----------
openwrt_print_success() {
  local pub_ip
  pub_ip="$(detect_public_ip)"
  echo
  echo "============================================================"
  echo "  ${C_BOLD}${C_GREEN}VPS 流量统计监控系统安装成功（OpenWrt）！${C_RESET}"
  echo "------------------------------------------------------------"
  if [ -n "$pub_ip" ]; then
    printf '  访问地址: %s%s%s\n' "${C_BOLD}${C_GREEN}" "http://${pub_ip}:${PORT}" "${C_RESET}"
  else
    warn "未能探测公网 IP，请用路由器地址访问:"
    printf '  访问地址: %s%s%s\n' "${C_BOLD}${C_GREEN}" "http://<路由器IP>:${PORT}" "${C_RESET}"
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
  echo "  服务管理: /etc/init.d/vpsmon status | restart"
  echo "  查看日志: logread | grep vpsmon（实时: logread -f | grep vpsmon）"
  echo "  一键卸载: sudo bash $APP_DIR/uninstall.sh"
  echo "============================================================"
  echo
  echo "${C_YELLOW}安全提示:${C_RESET}"
  echo "  1. OpenWrt 上服务以 root 运行（procd 惯例，无降权用户），仅供可信网络/本机使用！"
  echo "  2. 数据/配置在 overlay 目录 $OPENWRT_DATA_DIR（重启保留；/var 为 tmpfs 不可用）"
  echo "  3. 若忘记 token，可编辑 $OPENWRT_CONFIG_FILE 后执行: /etc/init.d/vpsmon restart"
  echo "  4. 防火墙仅放行了 lan 来源（uci 规则 vpsmon）；wan 访问建议反向代理 + TLS，勿明文暴露"
}

# ---------- systemd 版本检测（T2: 单元按目标版本分档生成） ----------
# 解析 systemctl --version 首行主版本号（如 "systemd 254 (254.5-1ubuntu3.1)" → 254）。
# 解析失败置 0，按最保守的通用档生成——版本不足的指令绝不出现在单元里。
detect_systemd_version() {
  local raw=""
  SYSTEMD_VERSION="0"
  if command -v systemctl >/dev/null 2>&1; then
    raw="$(systemctl --version 2>/dev/null | head -n1 || true)"
  fi
  if [ -z "$raw" ] && command -v systemd >/dev/null 2>&1; then
    raw="$(systemd --version 2>/dev/null | head -n1 || true)"
  fi
  local parsed
  parsed="$(printf '%s\n' "$raw" | sed -n 's/^systemd[[:space:]]\{1,\}\([0-9][0-9]*\).*/\1/p' || true)"
  case "$parsed" in
    ''|*[!0-9]*) SYSTEMD_VERSION="0" ;;
    *) SYSTEMD_VERSION="$parsed" ;;
  esac
}

# 加固档位标签（仅用于安装输出提示）: <230 通用档 / 230-243 增强档 / ≥244 完整档
systemd_tier_label() {
  local v="${1:-0}"
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  if [ "$v" -ge 244 ]; then printf '完整档'
  elif [ "$v" -ge 230 ]; then printf '增强档'
  else printf '通用档'; fi
}

# ---------- vpsmon.service 单元分块（T2: 按版本拼接） ----------
# 各指令的最低 systemd 版本（依据 systemd NEWS/man 页 "Added in version" 标注，
# 与 docs/SECURITY.md §4.9 一致）:
#   通用档（≥219 全兼容）: NoNewPrivileges(187) PrivateTmp(183) ProtectSystem=full(183)
#     ProtectHome(184) ReadWritePaths(183)
#   增强档: UMask(229) | ProtectKernelTunables/Modules/ControlGroups/RemoveIPC(230) |
#     RestrictSUIDSGID/RestrictRealtime/LockPersonality/SystemCallArchitectures(231) |
#     RestrictNamespaces(233)
#   完整档（≥244）: ProtectSystem=strict(232) ProtectKernelLogs(232) PrivateDevices(229)
#     ProtectClock(241) ProtectProc(244) CapabilityBoundingSet(古老，任意版本)
# 第一性原理: 老版本 systemd 对不认识的指令只报 "Failed to parse ... ignoring" 后静默
# 忽略——加固静默失效且日志刷屏，因此版本不足的指令绝不出现在单元里。

service_unit_header() {
  cat <<'EOF'
# VPS 流量统计监控系统 systemd 单元文件
# 本文件由 install.sh 在安装时按目标 systemd 版本动态生成，请勿手工修改；
# 重新安装（sudo bash install.sh ...）会按当前 systemd 版本重新生成。
# 安装/卸载/启停: systemctl {enable --now, disable --now, status, restart} vpsmon
#
# 安全加固依据: docs/SECURITY.md §4.9（M7/M8）
#   - /opt/vpsmon 归 root:root 只读；ProtectSystem=full 保护 /usr /boot /etc，
#     systemd ≥244 的完整档升级为 strict（除 ReadWritePaths 外全只读，含 /opt）。
#   - 服务以 User=vpsmon 降权运行；SQLite 新建文件默认 600（目录 700 为兜底）。
#   - 版本分档: 通用档(≥219) / 增强档(≥230) / 完整档(≥244)。
#     版本不足的指令绝不出现在本文件中——老版本 systemd 对不认识的指令只报
#     "Failed to parse ... ignoring" 后静默忽略，加固失效且日志刷屏。

[Unit]
Description=VPS Monitor - traffic statistics web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vpsmon
Group=vpsmon
# 入口: venv python 运行 vpsmon 包; 配置指向 /var/lib/vpsmon/config.json
ExecStart=/opt/vpsmon/venv/bin/python -m vpsmon.app --config /var/lib/vpsmon/config.json
WorkingDirectory=/opt/vpsmon
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1

# ---- 通用档（systemd ≥219 均支持）----
NoNewPrivileges=true
PrivateTmp=true
# ProtectSystem=full: 保护 /usr /boot /etc
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/vpsmon
EOF
}

# UMask（≥229）: SQLite vpsmon.db/-wal/-shm 默认 600（老版本无 UMask 时靠目录 700 兜底）
service_unit_umask() {
  cat <<'EOF'

# ---- 增强档: UMask（systemd ≥229; SQLite 新文件默认 600）----
UMask=0077
EOF
}

# 内核/资源保护（≥230）
service_unit_kernel() {
  cat <<'EOF'

# ---- 增强档: 内核与资源保护（systemd ≥230）----
# ProtectKernelTunables: psutil 只读 /proc/sys，不受影响
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RemoveIPC=true
EOF
}

# seccomp/能力限制（≥231）
service_unit_seccomp() {
  cat <<'EOF'

# ---- 增强档: seccomp 与能力限制（systemd ≥231）----
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
EOF
}

# namespace 限制（≥233）
service_unit_namespaces() {
  cat <<'EOF'

# ---- 增强档: namespace 限制（systemd ≥233）----
RestrictNamespaces=true
EOF
}

# 完整档（≥244）: strict 实际需 ≥232、ProtectProc 需 ≥244，统一在 ≥244 档位启用
service_unit_full() {
  cat <<'EOF'

# ---- 完整档（systemd ≥244）----
# ProtectSystem=strict: 除 ReadWritePaths 外全只读（含 /opt/vpsmon，M7）
ProtectSystem=strict
# ProtectProc=invisible: psutil 读 /proc 顶层文件，兼容；部署后实测确认
ProtectProc=invisible
ProtectKernelLogs=true
ProtectClock=true
# PrivateDevices: 私有 /dev（含 urandom，Python secrets 可用）
PrivateDevices=true
# CapabilityBoundingSet: 空集合，服务无需任何 capability
CapabilityBoundingSet=
EOF
}

service_unit_footer() {
  cat <<'EOF'

# ---- 不启用（与 Python/psutil 不兼容，务必保留注释说明，不要打开）----
# MemoryDenyWriteExecute=true  # CPython/libffi（psutil 的 C 扩展）需要 W^X 内存映射，
#                              # 启用后服务启动即崩溃（实测文档记录）
# ProcSubset=pid               # psutil 依赖完整 /proc（/proc/net/dev、/proc/stat 等），
#                              # 启用后采集全部失效
# PrivateUsers=true            # 改变文件属主映射语义，易致数据目录权限错乱
# IPAddressDeny=any            # 会阻断服务自身创建监听 socket，导致无法绑定端口

# ---- 可用但需逐项实测（本期不强制）----
# RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
# SystemCallFilter=@system-service   # Python 动态特性多，需充分回归

[Install]
WantedBy=multi-user.target
EOF
}

# 按目标 systemd 主版本生成完整单元（纯函数，供安装与 --selftest 复用）
generate_service_unit_for() {
  local v="${1:-0}"
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  service_unit_header
  if [ "$v" -ge 229 ]; then service_unit_umask; fi
  if [ "$v" -ge 230 ]; then service_unit_kernel; fi
  if [ "$v" -ge 231 ]; then service_unit_seccomp; fi
  if [ "$v" -ge 233 ]; then service_unit_namespaces; fi
  if [ "$v" -ge 244 ]; then service_unit_full; fi
  service_unit_footer
}

# ---------- 自检（T2: systemd 单元分档生成断言；无需 root） ----------
# 用法: sudo bash install.sh --selftest（或 bash install.sh --selftest）
# 模拟各 systemd 主版本号调用 generate_service_unit_for，断言生成内容
# 包含/不包含对应指令（版本不足的指令绝不允许出现）。
selftest() {
  local checks=0 pass=0 fail=0
  local ver unit lbl

  # $1=版本 $2=单元内容 $3=应包含的字符串 $4=说明
  assert_contains() {
    checks=$((checks + 1))
    case "$2" in
      *"$3"*) pass=$((pass + 1)) ;;
      *) fail=$((fail + 1)); printf '  [FAIL] v%s 应包含: %s（%s）\n' "$1" "$3" "$4" ;;
    esac
  }
  # $1=版本 $2=单元内容 $3=不应包含的字符串 $4=说明
  assert_not_contains() {
    checks=$((checks + 1))
    case "$2" in
      *"$3"*) fail=$((fail + 1)); printf '  [FAIL] v%s 不应包含: %s（%s）\n' "$1" "$3" "$4" ;;
      *) pass=$((pass + 1)) ;;
    esac
  }

  printf '%s\n' "== systemd 单元分档生成自检（模拟 219/228/229/230/231/233/244/254）=="
  for ver in 219 228 229 230 231 233 244 254; do
    unit="$(generate_service_unit_for "$ver")"

    # 通用档: 所有版本都必须包含
    assert_contains "$ver" "$unit" "[Unit]" "单元节"
    assert_contains "$ver" "$unit" "After=network-online.target" "网络就绪依赖"
    assert_contains "$ver" "$unit" "ExecStart=/opt/vpsmon/venv/bin/python -m vpsmon.app --config /var/lib/vpsmon/config.json" "T1 入口(-m vpsmon.app)不回退"
    assert_contains "$ver" "$unit" "User=vpsmon" "降权用户"
    assert_contains "$ver" "$unit" "Group=vpsmon" "降权用户组"
    assert_contains "$ver" "$unit" "NoNewPrivileges=true" "通用档"
    assert_contains "$ver" "$unit" "ProtectSystem=full" "通用档"
    assert_contains "$ver" "$unit" "ProtectHome=true" "通用档"
    assert_contains "$ver" "$unit" "ReadWritePaths=/var/lib/vpsmon" "通用档"
    assert_contains "$ver" "$unit" "[Install]" "安装节"
    assert_contains "$ver" "$unit" "WantedBy=multi-user.target" "开机自启"
    assert_contains "$ver" "$unit" "MemoryDenyWriteExecute" "不兼容项注释保留"
    assert_contains "$ver" "$unit" "ProcSubset=pid" "不兼容项注释保留"

    # 版本不足: 对应指令绝不允许出现
    if [ "$ver" -lt 229 ]; then
      assert_not_contains "$ver" "$unit" "UMask=" "UMask 需 systemd ≥229（NAS ~228 报错根因）"
    fi
    if [ "$ver" -lt 230 ]; then
      assert_not_contains "$ver" "$unit" "ProtectKernelTunables=" "需 ≥230"
      assert_not_contains "$ver" "$unit" "ProtectKernelModules=" "需 ≥230"
      assert_not_contains "$ver" "$unit" "ProtectControlGroups=" "需 ≥230"
      assert_not_contains "$ver" "$unit" "RemoveIPC=" "需 ≥230"
    fi
    if [ "$ver" -lt 231 ]; then
      assert_not_contains "$ver" "$unit" "RestrictSUIDSGID=" "需 ≥231"
      assert_not_contains "$ver" "$unit" "RestrictRealtime=" "需 ≥231"
      assert_not_contains "$ver" "$unit" "LockPersonality=" "需 ≥231"
      assert_not_contains "$ver" "$unit" "SystemCallArchitectures=" "需 ≥231"
    fi
    if [ "$ver" -lt 233 ]; then
      assert_not_contains "$ver" "$unit" "RestrictNamespaces=" "需 ≥233"
    fi
    if [ "$ver" -lt 244 ]; then
      assert_not_contains "$ver" "$unit" "ProtectSystem=strict" "strict 需 ≥244（本档位）"
      assert_not_contains "$ver" "$unit" "ProtectProc=invisible" "需 ≥244"
      assert_not_contains "$ver" "$unit" "ProtectKernelLogs=" "需 ≥244（本档位）"
      assert_not_contains "$ver" "$unit" "ProtectClock=" "需 ≥244（本档位）"
      assert_not_contains "$ver" "$unit" "PrivateDevices=" "需 ≥244（本档位）"
      assert_not_contains "$ver" "$unit" "CapabilityBoundingSet=" "需 ≥244（本档位）"
    fi

    # 达到阈值: 对应指令必须出现
    if [ "$ver" -ge 229 ]; then
      assert_contains "$ver" "$unit" "UMask=0077" "UMask 档位"
    fi
    if [ "$ver" -ge 230 ]; then
      assert_contains "$ver" "$unit" "ProtectKernelTunables=true" "增强档"
      assert_contains "$ver" "$unit" "ProtectControlGroups=true" "增强档"
      assert_contains "$ver" "$unit" "RemoveIPC=true" "增强档"
    fi
    if [ "$ver" -ge 231 ]; then
      assert_contains "$ver" "$unit" "RestrictSUIDSGID=true" "增强档"
      assert_contains "$ver" "$unit" "RestrictRealtime=true" "增强档"
      assert_contains "$ver" "$unit" "LockPersonality=true" "增强档"
      assert_contains "$ver" "$unit" "SystemCallArchitectures=native" "增强档"
    fi
    if [ "$ver" -ge 233 ]; then
      assert_contains "$ver" "$unit" "RestrictNamespaces=true" "增强档"
    fi
    if [ "$ver" -ge 244 ]; then
      assert_contains "$ver" "$unit" "ProtectSystem=strict" "完整档"
      assert_contains "$ver" "$unit" "ProtectProc=invisible" "完整档"
      assert_contains "$ver" "$unit" "ProtectKernelLogs=true" "完整档"
      assert_contains "$ver" "$unit" "ProtectClock=true" "完整档"
      assert_contains "$ver" "$unit" "PrivateDevices=true" "完整档"
      assert_contains "$ver" "$unit" "CapabilityBoundingSet=" "完整档"
    fi

    # ---- T7: systemd 不支持行尾内联注释——值行绝不允许出现 # 或 ; ----
    # （行首 #/; 为注释行，空白行跳过；其余行含 # 或 ; 即失败。历史上
    #   "ProtectSystem=strict # 更强: ..." 被解析为值的一部分 → 日志
    #   "Failed to parse ProtectSystem=strict # ... ignoring"）
    trailing="$(printf '%s\n' "$unit" | grep -vE '^[[:space:]]*$' \
                | grep -vE '^[#;]' | grep -E '[#;]' || true)"
    checks=$((checks + 1))
    if [ -n "$trailing" ]; then
      fail=$((fail + 1))
      printf '  [FAIL] v%s 值行含行尾注释（systemd 不支持，T7 根因）:\n%s\n' "$ver" "$trailing"
    else
      pass=$((pass + 1))
    fi
  done

  # ---- T7: 参考模板 vpsmon.service 同样不得含行尾内联注释（静态文件守卫） ----
  if [ -r "$SCRIPT_DIR/vpsmon.service" ]; then
    checks=$((checks + 1))
    tpl_bad="$(grep -vE '^[[:space:]]*$' "$SCRIPT_DIR/vpsmon.service" \
               | grep -vE '^[#;]' | grep -E '[#;]' || true)"
    if [ -n "$tpl_bad" ]; then
      fail=$((fail + 1))
      printf '  [FAIL] 参考模板 vpsmon.service 值行含行尾注释:\n%s\n' "$tpl_bad"
    else
      pass=$((pass + 1))
    fi
  fi

  # 档位标签映射: <230 通用档 / 230-243 增强档 / ≥244 完整档
  lbl="$(systemd_tier_label 219)"; [ "$lbl" = "通用档" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); printf '  [FAIL] 219 档位标签=%s（期望 通用档）\n' "$lbl"; }
  lbl="$(systemd_tier_label 228)"; [ "$lbl" = "通用档" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); printf '  [FAIL] 228 档位标签=%s（期望 通用档）\n' "$lbl"; }
  lbl="$(systemd_tier_label 230)"; [ "$lbl" = "增强档" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); printf '  [FAIL] 230 档位标签=%s（期望 增强档）\n' "$lbl"; }
  lbl="$(systemd_tier_label 243)"; [ "$lbl" = "增强档" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); printf '  [FAIL] 243 档位标签=%s（期望 增强档）\n' "$lbl"; }
  lbl="$(systemd_tier_label 244)"; [ "$lbl" = "完整档" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); printf '  [FAIL] 244 档位标签=%s（期望 完整档）\n' "$lbl"; }
  lbl="$(systemd_tier_label 254)"; [ "$lbl" = "完整档" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); printf '  [FAIL] 254 档位标签=%s（期望 完整档）\n' "$lbl"; }
  checks=$((checks + 6))

  # ---- OpenWrt 分支静态断言（T5: 函数存在、边界隔离、关键片段；仅当能读取脚本文件时） ----
  if [ -r "$0" ] && grep -q '^is_openwrt()' "$0" 2>/dev/null; then
    printf '%s\n' "== OpenWrt 分支静态断言 =="
    # 提取函数体（awk: 从 ^name() { 到匹配的 ^}，跳过 heredoc 内容——procd 模板内部
    # 含行首 } 与 start_service() {），断言不引用 systemd 系/其它包管理器命令
    assert_openwrt_clean() {
      local body
      body="$(awk -v fn="$1" '
        $0 == fn "() {" { f=1; next }
        !f { next }
        inhere != "" { if ($0 == inhere) inhere=""; next }
        /<<'"'"'EOF'"'"'$/ || /<<EOF$/ { inhere="EOF"; next }
        $0 == "}" { f=0 }
        f { print }
      ' "$0" 2>/dev/null || true)"
      checks=$((checks + 1))
      if printf '%s\n' "$body" | grep -qE 'systemctl|journalctl|apt-get|dnf |yum |apk '; then
        fail=$((fail + 1))
        printf '  [FAIL] OpenWrt 函数 %s 引用了 systemd/其它包管理器命令（边界隔离被破坏）\n' "$1"
      else
        pass=$((pass + 1))
      fi
    }
    # 1) OpenWrt 分支函数必须存在
    for fn in is_openwrt openwrt_install_service openwrt_start_and_check \
              openwrt_firewall_allow openwrt_firewall_revoke openwrt_do_uninstall \
              openwrt_print_success; do
      checks=$((checks + 1))
      if grep -q "^${fn}()" "$0"; then
        pass=$((pass + 1))
      else
        fail=$((fail + 1)); printf '  [FAIL] 缺少 OpenWrt 分支函数: %s\n' "$fn"
      fi
      assert_openwrt_clean "$fn"
    done
    # 2) OpenWrt 常量必须存在
    for c in OPENWRT_DATA_DIR OPENWRT_CONFIG_FILE OPENWRT_INIT_FILE OPENWRT_FIREWALL_MARKER; do
      checks=$((checks + 1))
      if grep -q "^${c}=" "$0"; then
        pass=$((pass + 1))
      else
        fail=$((fail + 1)); printf '  [FAIL] 缺少 OpenWrt 常量: %s\n' "$c"
      fi
    done
    # 3) 关键代码片段（opkg/apk 包管理/procd/uci/模块校验/is_openwrt）
    checks=$((checks + 1))
    if grep -q 'OPENWRT_PLATFORM=1' "$0" \
       && grep -q 'opkg update' "$0" \
       && grep -q 'apk update' "$0" \
       && grep -q 'import sqlite3, http.server' "$0" \
       && grep -q 'procd_open_instance' "$0" \
       && grep -q 'procd_set_param respawn' "$0" \
       && grep -q 'uci add firewall rule' "$0" \
       && grep -q '^is_openwrt()' "$0"; then
      pass=$((pass + 1))
    else
      fail=$((fail + 1)); printf '  [FAIL] OpenWrt 关键代码片段缺失（opkg/apk update/模块校验/procd/uci/is_openwrt）\n'
    fi
    # 4) detect_distro / install_system_deps 含 opkg 与 apk(OpenWrt) 分支
    checks=$((checks + 1))
    if grep -q '^detect_distro()' "$0" && grep -q 'opkg)' "$0" \
       && grep -q 'opkg install $PKG_PY' "$0" \
       && grep -q 'apk add $PKG_PY' "$0" \
       && grep -q 'OPENWRT_PLATFORM=1' "$0"; then
      pass=$((pass + 1))
    else
      fail=$((fail + 1)); printf '  [FAIL] detect_distro/install_system_deps 缺少 opkg/apk(OpenWrt) 分支\n'
    fi
  else
    warn "跳过 OpenWrt 静态断言（无法读取脚本文件 $0，可能经 stdin 管道执行）"
  fi

  echo
  printf '%s\n' "== 自检结果: 通过 $pass / $checks，失败 $fail =="
  if [ "$fail" -gt 0 ]; then
    return 1
  fi
  printf '%s\n' "自检全部通过。"
}

# ---------- 安装 systemd 服务（T2: 单元按目标 systemd 版本分档动态生成） ----------
install_service() {
  if [ ! -f "$SCRIPT_DIR/vpsmon.service" ]; then
    err "未找到 $SCRIPT_DIR/vpsmon.service（仓库中的参考模板）"
    exit 1
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "未检测到 systemd（当前系统可能使用 OpenRC/OpenWrt procd 等 init），跳过服务注册"
    return 1
  fi
  detect_systemd_version
  local tier
  tier="$(systemd_tier_label "$SYSTEMD_VERSION")"
  if [ "$SYSTEMD_VERSION" = "0" ]; then
    info "systemd 版本解析失败，按最保守的通用档（≥219）生成单元"
  else
    info "systemd 版本: ${SYSTEMD_VERSION}（加固档位: ${tier}）"
  fi
  info "安装 systemd 服务 $SERVICE_FILE（单元按 systemd ${SYSTEMD_VERSION} 动态生成）"
  generate_service_unit_for "$SYSTEMD_VERSION" > "${SERVICE_FILE}.new"
  install -m 644 "${SERVICE_FILE}.new" "$SERVICE_FILE"
  rm -f "${SERVICE_FILE}.new"
  systemctl daemon-reload
  # 最佳努力复检: systemd-analyze verify 老版本也有该子命令；告警仅提示，不中断安装
  if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify "$SERVICE_FILE" >/dev/null 2>&1; then
      info "systemd-analyze verify 通过（单元无解析告警）"
    else
      warn "systemd-analyze verify 对 $SERVICE_FILE 有告警（仅提示，不影响安装）"
    fi
  fi
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
  # OpenWrt: uci firewall（fw3/firewall4）分支（SPEC §13.3.6），与 ufw/firewalld 完全隔离
  if [ "$OPENWRT_PLATFORM" = "1" ]; then
    openwrt_firewall_allow
    return $?
  fi
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
  # OpenWrt: uci 标记（uci|<段名>）撤销分支（SPEC §13.3.6/13.3.7）
  if is_openwrt; then
    openwrt_firewall_revoke
    return $?
  fi
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
  if [ "$OPENWRT_PLATFORM" = "1" ]; then
    openwrt_print_success
    return $?
  fi
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

  # OpenWrt 分支（SPEC §13.3.7）: 卸载时 PKG_MGR 未设置，用 is_openwrt 判定
  if is_openwrt; then
    openwrt_do_uninstall
    return $?
  fi

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
    if is_openwrt; then
      err "OpenWrt 请先安装 curl: opkg install curl ca-bundle（opkg 系）或 apk add curl ca-bundle（apk 系）"
    fi
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
  if [ "$SELFTEST" = "1" ]; then
    selftest
    exit 0
  fi

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
  setup_venv               # OpenWrt 分支内部跳过（纯标准库，无 venv/pip）
  write_config             # OpenWrt 分支写到 /etc/vpsmon/config.json（overlay）

  if [ "$OPENWRT_PLATFORM" = "1" ]; then
    # OpenWrt 分支（SPEC §13.3）: procd 服务 + curl 自检，完全不走 systemd 路径
    if ! openwrt_install_service; then
      err "安装未完全成功。"
      exit 1
    fi
    if ! openwrt_start_and_check; then
      err "安装未完全成功。"
      err "请查看日志排障: logread | grep vpsmon"
      exit 1
    fi
  else
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
  fi

  firewall_allow
  print_success
}

main "$@"
