#!/usr/bin/env bash
# =============================================================================
# VPS 流量统计监控系统 — 一键卸载脚本（自包含，支持远程一行执行）
#
# 用法:
#   sudo bash uninstall.sh                 # 卸载（交互确认是否删除数据）
#   sudo bash uninstall.sh --keep-data     # 卸载并保留 /var/lib/vpsmon 数据
#
# 本脚本完全自包含，不依赖同目录任何文件（无 BASH_SOURCE[0] 依赖），
# 可通过远程 curl 一行执行（仓库: github.com/ruoshui6662/vps-traffic-watch）:
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/uninstall.sh)"
#   # 或管道方式（非交互模式：stdin 非终端，默认保留数据目录，不会阻塞等待输入）:
#   curl -fsSL https://raw.githubusercontent.com/ruoshui6662/vps-traffic-watch/main/uninstall.sh | sudo bash
#
# 卸载流程: root 检查 → 停止并禁用服务 → 撤销安装时自动添加的防火墙规则 →
#           删除 systemd 单元并 daemon-reload → 删除程序目录 /opt/vpsmon →
#           交互确认或 --keep-data 决定是否删除数据目录 /var/lib/vpsmon →
#           删除系统用户 vpsmon
# OpenWrt 分支（SPEC §13.3.7，自动识别）: /etc/init.d/vpsmon stop+disable →
#           撤销 uci 防火墙规则（标记 /etc/vpsmon/.firewall-rule）→ 删 init 脚本与
#           /opt/vpsmon → 交互确认或 --keep-data 决定是否删除 /etc/vpsmon 数据目录
#           （不卸载 python3/curl/ca-bundle 等 opkg/apk 包，可能被其他包依赖）
# =============================================================================
set -euo pipefail

# ---------- 常量 ----------
APP_DIR="/opt/vpsmon"              # 程序目录（vpsmon 包 + requirements.txt + venv + uninstall.sh）
DATA_DIR="/var/lib/vpsmon"         # 数据目录（config.json + vpsmon.db + .firewall-rule）
SERVICE_NAME="vpsmon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
FIREWALL_MARKER="${DATA_DIR}/.firewall-rule"   # 安装时自动放行防火墙规则的记录
# OpenWrt（SPEC §13.3.3）: /var 为 tmpfs 重启清空，数据/配置在 overlay 的 /etc/vpsmon
OPENWRT_DATA_DIR="/etc/vpsmon"
OPENWRT_INIT_FILE="/etc/init.d/vpsmon"
OPENWRT_FIREWALL_MARKER="${OPENWRT_DATA_DIR}/.firewall-rule"

# ---------- 参数 ----------
KEEP_DATA=0

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
用法: sudo bash uninstall.sh [选项]
      sudo bash uninstall.sh uninstall [--keep-data]   # 兼容 install.sh uninstall 的写法

选项:
  --keep-data        卸载时保留 /var/lib/vpsmon 数据目录
  -h, --help         显示本帮助
EOF
}

# ---------- 参数解析 ----------
while [ $# -gt 0 ]; do
  case "$1" in
    uninstall)     shift ;;            # 兼容 `install.sh uninstall` 的用法，忽略该关键字
    --keep-data)   KEEP_DATA=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) err "未知参数: $1"; usage; exit 1 ;;
  esac
done

# ---------- root 检查 ----------
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "需要 root 权限，请使用: sudo bash uninstall.sh"
    exit 1
  fi
}

# ---------- OpenWrt 平台判定（SPEC §13.3.1: /etc/openwrt_release 或 opkg/apk 或 os-release；含 ImmortalWrt） ----------
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

# ---------- OpenWrt 卸载主流程（SPEC §13.3.7: 无 systemd，走 procd/uci；不卸载 opkg/apk 包） ----------
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
  # 4. 删除程序目录（含 uninstall.sh 自身；脚本已载入内存，删除不影响执行）
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
  # 6. 不卸载 python3/curl/ca-bundle 等 opkg/apk 包（可能被其他包依赖，超出本应用职责）
  echo
  info "卸载完成。（未卸载 python3/curl/ca-bundle 等 opkg/apk 包——它们可能被其他包依赖）"
}

# ---------- 撤销安装时自动添加的防火墙规则（SECURITY.md §4.10-C/S3） ----------
# 读取 /var/lib/vpsmon/.firewall-rule 标记 → 撤销对应规则 → 删除标记。
# 标记文件缺失则不撤销（避免误删用户既有规则）。
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

# ---------- 卸载主流程（与 install.sh 的 do_uninstall 行为一致） ----------
do_uninstall() {
  require_root
  echo
  info "开始卸载 VPS 流量统计监控系统..."

  # OpenWrt 分支（SPEC §13.3.7）: procd 服务 + uci 防火墙，完全不走 systemd 路径
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

  # 4. 删除程序目录（含 venv 与 uninstall.sh 自身；脚本已载入内存，删除不影响执行）
  if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
    info "已删除 $APP_DIR"
  fi

  # 5. 数据目录: --keep-data 保留；否则交互确认（默认保留）。
  #    远程管道执行时 stdin 不是终端，无法交互确认，为安全起见默认保留并给出提示。
  if [ "$KEEP_DATA" = "1" ]; then
    warn "已指定 --keep-data，保留数据目录 $DATA_DIR（含 config.json 与 vpsmon.db）"
  elif [ -d "$DATA_DIR" ]; then
    if [ -t 0 ]; then
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
    else
      warn "检测到非交互执行（stdin 非终端），跳过删除确认，默认保留数据目录 $DATA_DIR"
      warn "如需同时删除数据，请手动执行: rm -rf $DATA_DIR"
    fi
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

do_uninstall
