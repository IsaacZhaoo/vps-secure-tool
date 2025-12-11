#!/usr/bin/env bash
#
# vps_secure_tool.sh
# VPS 运维 + 安全加固工具箱（偏 Debian / Ubuntu）
# 支持中英文界面切换（默认根据系统 LANG 自动选择）
#
# 使用方式：
#   1. 拷贝到服务器：/usr/local/bin/vps-secure 或任意路径
#   2. chmod +x vps_secure_tool.sh
#   3. 以 root 或 sudo 运行：sudo ./vps_secure_tool.sh
#
# 说明：
#   - 尽量以"检查 + 交互确认"的方式进行变更，避免直接搞崩 SSH。
#   - 主要支持 Debian/Ubuntu + ufw + fail2ban 的常见组合。
#   - 一些功能（如添加用户）需要你在交互过程中输入用户名/密码。

# ============================================================
# VERSION - 版本信息
# ============================================================
VERSION="1.1.2"
SCRIPT_NAME="vps-secure-tool"
GITHUB_REPO="IsaacZhaoo/vps-secure-tool"
CONFIG_FILE="/etc/vps-secure-tool.conf"

set -e

# 信号处理：优雅退出
cleanup_and_exit() {
  echo
  echo -e "\033[33m[中断] 收到退出信号，正在清理...\033[0m"
  echo -e "\033[33m[Interrupted] Received exit signal, cleaning up...\033[0m"
  # 可以在这里添加清理逻辑
  exit 130
}
trap cleanup_and_exit INT TERM

# ============================================================
# CORE - 核心变量和函数
# ============================================================

# 颜色输出
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

# ============================================================
# CONFIG - 配置管理模块
# ============================================================

# 默认配置值
DEFAULT_USER=""
SSH_PORT=22
DISABLE_ROOT_LOGIN="yes"
DISABLE_PASSWORD_AUTH="yes"
ENABLE_UFW="yes"
UFW_ALLOW_PORTS="22,80,443"
AUTO_UPDATE_CHECK="true"
FAIL2BAN_BANTIME="1h"
FAIL2BAN_FINDTIME="10m"
FAIL2BAN_MAXRETRY="5"

# 加载配置文件
load_config() {
  if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
  fi
}

# 显示当前配置
show_config() {
  say "${GREEN}== 当前配置 ==${RESET}" \
      "${GREEN}== Current Configuration ==${RESET}"
  echo
  say "配置文件路径: $CONFIG_FILE" "Config file: $CONFIG_FILE"
  if [ -f "$CONFIG_FILE" ]; then
    say "状态: 已加载" "Status: Loaded"
  else
    say "状态: 使用默认值（配置文件不存在）" "Status: Using defaults (config file not found)"
  fi
  echo
  say "[用户配置]" "[User Settings]"
  echo "  DEFAULT_USER=$DEFAULT_USER"
  echo
  say "[SSH 配置]" "[SSH Settings]"
  echo "  SSH_PORT=$SSH_PORT"
  echo "  DISABLE_ROOT_LOGIN=$DISABLE_ROOT_LOGIN"
  echo "  DISABLE_PASSWORD_AUTH=$DISABLE_PASSWORD_AUTH"
  echo
  say "[防火墙配置]" "[Firewall Settings]"
  echo "  ENABLE_UFW=$ENABLE_UFW"
  echo "  UFW_ALLOW_PORTS=$UFW_ALLOW_PORTS"
  echo
  say "[Fail2Ban 配置]" "[Fail2Ban Settings]"
  echo "  FAIL2BAN_BANTIME=$FAIL2BAN_BANTIME"
  echo "  FAIL2BAN_FINDTIME=$FAIL2BAN_FINDTIME"
  echo "  FAIL2BAN_MAXRETRY=$FAIL2BAN_MAXRETRY"
  echo
  say "[更新配置]" "[Update Settings]"
  echo "  AUTO_UPDATE_CHECK=$AUTO_UPDATE_CHECK"
}

# 编辑配置文件
edit_config() {
  if [ ! -f "$CONFIG_FILE" ]; then
    say "${YELLOW}[提示] 配置文件不存在，是否创建？${RESET}" \
        "${YELLOW}[Note] Config file does not exist. Create it?${RESET}"
    local create_conf
    ask "[y/N]: " "[y/N]: " create_conf
    if [[ "$create_conf" =~ ^[yY]$ ]]; then
      # 复制示例配置
      local script_dir
      script_dir="$(cd "$(dirname "$0")" && pwd)"
      if [ -f "${script_dir}/vps-secure-tool.conf.example" ]; then
        cp "${script_dir}/vps-secure-tool.conf.example" "$CONFIG_FILE"
      else
        # 创建基本配置
        cat > "$CONFIG_FILE" <<'CONFEOF'
# VPS Secure Tool Configuration
DEFAULT_USER=""
SSH_PORT=22
DISABLE_ROOT_LOGIN="yes"
ENABLE_UFW="yes"
UFW_ALLOW_PORTS="22,80,443"
AUTO_UPDATE_CHECK="true"
CONFEOF
      fi
      chmod 600 "$CONFIG_FILE"
      say "${GREEN}[完成] 已创建配置文件: $CONFIG_FILE${RESET}" \
          "${GREEN}[Done] Created config file: $CONFIG_FILE${RESET}"
    else
      return
    fi
  fi

  # 使用可用的编辑器
  local editor
  if command -v nano >/dev/null 2>&1; then
    editor="nano"
  elif command -v vim >/dev/null 2>&1; then
    editor="vim"
  elif command -v vi >/dev/null 2>&1; then
    editor="vi"
  else
    say "${RED}[错误] 未找到可用的编辑器（nano/vim/vi）${RESET}" \
        "${RED}[ERROR] No editor found (nano/vim/vi)${RESET}"
    return
  fi

  $editor "$CONFIG_FILE"
  say "${GREEN}[提示] 配置已保存，重新加载中...${RESET}" \
      "${GREEN}[Note] Config saved, reloading...${RESET}"
  load_config
}

# --- 配置备份与恢复 ---
BACKUP_DIR="/var/backups/vps-secure-tool"

list_backups() {
  say "${GREEN}== 可用备份列表 ==${RESET}" \
      "${GREEN}== Available Backups ==${RESET}"
  echo

  if [ ! -d "$BACKUP_DIR" ]; then
    say "备份目录不存在: $BACKUP_DIR" "Backup directory does not exist: $BACKUP_DIR"
    say "尚无任何备份。" "No backups available."
    return 1
  fi

  local backups
  backups=$(ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null | sort -r)

  if [ -z "$backups" ]; then
    say "备份目录为空，尚无任何备份。" "Backup directory is empty, no backups available."
    return 1
  fi

  local count=1
  while IFS= read -r backup_file; do
    local filename size date_str
    filename=$(basename "$backup_file")
    size=$(du -h "$backup_file" 2>/dev/null | cut -f1)
    # 从文件名提取日期: backup-YYYYMMDD-HHMMSS.tar.gz
    date_str=$(echo "$filename" | grep -oP '\d{8}-\d{6}' | sed 's/\(....\)\(..\)\(..\)-\(..\)\(..\)\(..\)/\1-\2-\3 \4:\5:\6/')
    echo "  $count) $filename ($size) - $date_str"
    ((count++))
  done <<< "$backups"

  return 0
}

backup_config() {
  say "${GREEN}== 备份安全配置 ==${RESET}" \
      "${GREEN}== Backup Security Configuration ==${RESET}"
  echo

  # 创建备份目录
  if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
  fi

  local timestamp
  timestamp=$(date '+%Y%m%d-%H%M%S')
  local backup_file="$BACKUP_DIR/backup-${timestamp}.tar.gz"
  local tmp_dir="/tmp/vps-backup-$$"

  say "将备份以下配置文件：" "Will backup the following configuration files:"
  echo "  - /etc/ssh/sshd_config"
  echo "  - /etc/ssh/sshd_config.d/* (如存在)"
  echo "  - /etc/ufw/* (如存在)"
  echo "  - /etc/fail2ban/jail.local (如存在)"
  echo "  - /etc/sysctl.d/99-*.conf (如存在)"
  echo "  - $CONFIG_FILE (如存在)"
  echo

  local confirm
  ask "是否继续备份？[Y/n]: " "Continue with backup? [Y/n]: " confirm
  if [[ "$confirm" =~ ^[nN]$ ]]; then
    say "已取消" "Cancelled"
    return
  fi

  # 创建临时目录
  mkdir -p "$tmp_dir"

  # 收集文件
  local files_to_backup=()

  # SSH 配置
  [ -f /etc/ssh/sshd_config ] && cp /etc/ssh/sshd_config "$tmp_dir/" && files_to_backup+=("sshd_config")
  if [ -d /etc/ssh/sshd_config.d ]; then
    mkdir -p "$tmp_dir/sshd_config.d"
    cp /etc/ssh/sshd_config.d/* "$tmp_dir/sshd_config.d/" 2>/dev/null && files_to_backup+=("sshd_config.d/")
  fi

  # UFW 配置
  if [ -d /etc/ufw ]; then
    mkdir -p "$tmp_dir/ufw"
    cp -r /etc/ufw/* "$tmp_dir/ufw/" 2>/dev/null && files_to_backup+=("ufw/")
  fi

  # fail2ban 配置
  [ -f /etc/fail2ban/jail.local ] && cp /etc/fail2ban/jail.local "$tmp_dir/" && files_to_backup+=("jail.local")

  # sysctl 配置
  mkdir -p "$tmp_dir/sysctl.d"
  cp /etc/sysctl.d/99-*.conf "$tmp_dir/sysctl.d/" 2>/dev/null && files_to_backup+=("sysctl.d/")

  # 脚本配置文件
  [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$tmp_dir/vps-secure-tool.conf" && files_to_backup+=("vps-secure-tool.conf")

  # 创建备份信息文件
  cat > "$tmp_dir/backup-info.txt" << EOF
VPS Secure Tool Backup
======================
Date: $(date '+%Y-%m-%d %H:%M:%S')
Hostname: $(hostname)
Script Version: $VERSION

Included files:
$(printf '  - %s\n' "${files_to_backup[@]}")
EOF

  # 打包
  say "正在创建备份..." "Creating backup..."
  if tar -czf "$backup_file" -C "$tmp_dir" . 2>/dev/null; then
    chmod 600 "$backup_file"
    local backup_size
    backup_size=$(du -h "$backup_file" | cut -f1)
    say "${GREEN}[完成] 备份已创建${RESET}" "${GREEN}[Done] Backup created${RESET}"
    echo
    echo "  文件: $backup_file"
    echo "  大小: $backup_size"
    echo "  内容: ${#files_to_backup[@]} 个配置项"
  else
    say "${RED}[错误] 备份创建失败${RESET}" "${RED}[Error] Backup creation failed${RESET}"
    rm -rf "$tmp_dir"
    return 1
  fi

  # 清理临时目录
  rm -rf "$tmp_dir"
}

restore_config() {
  say "${GREEN}== 恢复安全配置 ==${RESET}" \
      "${GREEN}== Restore Security Configuration ==${RESET}"
  echo

  # 列出可用备份
  if ! list_backups; then
    return 1
  fi

  echo
  local backup_num
  if [ "$LANG_MODE" = "zh" ]; then
    read -rp "请输入要恢复的备份编号 (留空取消): " backup_num
  else
    read -rp "Enter backup number to restore (empty to cancel): " backup_num
  fi

  if [ -z "$backup_num" ]; then
    say "已取消" "Cancelled"
    return
  fi

  # 获取对应的备份文件
  local backup_file
  backup_file=$(ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null | sort -r | sed -n "${backup_num}p")

  if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
    say "${RED}[错误] 无效的备份编号${RESET}" "${RED}[Error] Invalid backup number${RESET}"
    return 1
  fi

  say "选择的备份: $(basename "$backup_file")" "Selected backup: $(basename "$backup_file")"
  echo

  # 显示备份内容
  say "备份内容预览：" "Backup contents preview:"
  tar -tzf "$backup_file" | head -20
  echo

  say "${YELLOW}[警告] 恢复操作将覆盖当前配置文件！${RESET}" \
      "${YELLOW}[Warning] Restore will overwrite current configuration files!${RESET}"
  echo

  local confirm
  ask "确认恢复？[y/N]: " "Confirm restore? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[yY]$ ]]; then
    say "已取消" "Cancelled"
    return
  fi

  # 创建临时目录解压
  local tmp_dir="/tmp/vps-restore-$$"
  mkdir -p "$tmp_dir"

  say "正在解压备份..." "Extracting backup..."
  if ! tar -xzf "$backup_file" -C "$tmp_dir"; then
    say "${RED}[错误] 解压备份失败${RESET}" "${RED}[Error] Failed to extract backup${RESET}"
    rm -rf "$tmp_dir"
    return 1
  fi

  # 恢复各配置文件
  say "正在恢复配置文件..." "Restoring configuration files..."

  local restored=0

  # SSH 配置
  if [ -f "$tmp_dir/sshd_config" ]; then
    cp "$tmp_dir/sshd_config" /etc/ssh/sshd_config
    echo "  ✓ /etc/ssh/sshd_config"
    ((restored++))
  fi

  if [ -d "$tmp_dir/sshd_config.d" ]; then
    mkdir -p /etc/ssh/sshd_config.d
    cp "$tmp_dir/sshd_config.d/"* /etc/ssh/sshd_config.d/ 2>/dev/null
    echo "  ✓ /etc/ssh/sshd_config.d/"
    ((restored++))
  fi

  # UFW 配置
  if [ -d "$tmp_dir/ufw" ]; then
    cp -r "$tmp_dir/ufw/"* /etc/ufw/ 2>/dev/null
    echo "  ✓ /etc/ufw/"
    ((restored++))
  fi

  # fail2ban 配置
  if [ -f "$tmp_dir/jail.local" ]; then
    mkdir -p /etc/fail2ban
    cp "$tmp_dir/jail.local" /etc/fail2ban/jail.local
    echo "  ✓ /etc/fail2ban/jail.local"
    ((restored++))
  fi

  # sysctl 配置
  if [ -d "$tmp_dir/sysctl.d" ] && ls "$tmp_dir/sysctl.d/"*.conf &>/dev/null; then
    cp "$tmp_dir/sysctl.d/"*.conf /etc/sysctl.d/ 2>/dev/null
    echo "  ✓ /etc/sysctl.d/"
    ((restored++))
  fi

  # 脚本配置
  if [ -f "$tmp_dir/vps-secure-tool.conf" ]; then
    cp "$tmp_dir/vps-secure-tool.conf" "$CONFIG_FILE"
    echo "  ✓ $CONFIG_FILE"
    ((restored++))
  fi

  # 清理
  rm -rf "$tmp_dir"

  echo
  say "${GREEN}[完成] 已恢复 $restored 个配置项${RESET}" \
      "${GREEN}[Done] Restored $restored configuration items${RESET}"
  echo

  # 提示重启服务
  say "${YELLOW}[提示] 建议重启相关服务以应用配置：${RESET}" \
      "${YELLOW}[Note] Consider restarting services to apply configuration:${RESET}"
  echo "  systemctl restart sshd"
  echo "  ufw reload"
  echo "  systemctl restart fail2ban"
  echo "  sysctl --system"
  echo

  local restart_confirm
  ask "是否现在重启这些服务？[y/N]: " "Restart these services now? [y/N]: " restart_confirm
  if [[ "$restart_confirm" =~ ^[yY]$ ]]; then
    say "正在重启服务..." "Restarting services..."
    systemctl restart sshd 2>/dev/null && echo "  ✓ sshd"
    ufw reload 2>/dev/null && echo "  ✓ ufw"
    systemctl restart fail2ban 2>/dev/null && echo "  ✓ fail2ban"
    sysctl --system > /dev/null 2>&1 && echo "  ✓ sysctl"
    say "${GREEN}[完成] 服务已重启${RESET}" "${GREEN}[Done] Services restarted${RESET}"
  fi
}

# 界面语言模式：zh 或 en
LANG_MODE="zh"

# 根据系统 LANG 简单自动选择默认语言
if [ -n "$LANG" ]; then
  case "$LANG" in
    zh_*|ZH_*) LANG_MODE="zh" ;;
    *) LANG_MODE="en" ;;
  esac
fi

toggle_lang() {
  if [ "$LANG_MODE" = "zh" ]; then
    LANG_MODE="en"
  else
    LANG_MODE="zh"
  fi
}

# 通用输出函数
say() {
  local zh="$1"
  local en="$2"
  if [ "$LANG_MODE" = "zh" ]; then
    echo -e "$zh"
  else
    echo -e "$en"
  fi
}

# 通用输入提示函数
ask() {
  local zh="$1"
  local en="$2"
  local __varname="$3"
  if [ "$LANG_MODE" = "zh" ]; then
    read -rp "$zh" "$__varname"
  else
    read -rp "$en" "$__varname"
  fi
}

need_root() {
  if [ "$EUID" -ne 0 ]; then
    say "${RED}[错误] 本脚本需要 root 权限，请使用 sudo 运行。${RESET}" \
        "${RED}[ERROR] This script must be run as root (use sudo).${RESET}"
    exit 1
  fi
}

check_distro() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID=$ID
    DISTRO_LIKE=$ID_LIKE
  else
    DISTRO_ID="unknown"
    DISTRO_LIKE=""
  fi
}

is_debian_like() {
  [[ "$DISTRO_ID" == "debian" || "$DISTRO_ID" == "ubuntu" || "$DISTRO_LIKE" == *"debian"* ]]
}

print_header() {
  echo -e "${CYAN}"
  echo "===================================================="
  if [ "$LANG_MODE" = "zh" ]; then
    echo "  VPS 运维 + 安全加固工具箱"
  else
    echo "  VPS Ops + Security Toolbox"
  fi
  echo "===================================================="
  echo -e "${RESET}"
}

pause() {
  local dummy
  ask "按回车键继续..." "Press Enter to continue..." dummy
}

# ============================================================
# INIT - 系统初始化模块
# ============================================================

show_basic_info() {
  say "${GREEN}== 系统基础信息 ==${RESET}" \
      "${GREEN}== Basic system info ==${RESET}"

  if command -v hostnamectl >/dev/null 2>&1; then
    hostnamectl
  else
    say "主机名：$(hostname)" "Hostname: $(hostname)"
  fi

  if [ -f /etc/os-release ]; then
    echo
    say "发行版信息：" "OS release info:"
    cat /etc/os-release
  fi

  echo
  say "内核版本：" "Kernel version:"
  uname -a

  echo
  say "网络接口与 IP：" "Network interfaces and IP addresses:"
  ip addr || ip a || true
  echo
}

show_resource_usage() {
  say "${GREEN}== 系统资源使用情况 ==${RESET}" \
      "${GREEN}== System resource usage ==${RESET}"

  echo
  say "[内存使用情况]:" "[Memory usage]:"
  free -h || true

  echo
  say "[磁盘使用情况]:" "[Disk usage]:"
  df -h || true

  echo
  say "[按内存占用排序的前 10 个进程]:" "[Top 10 processes by memory usage]:"
  ps aux --sort=-%mem | head -n 11 || true
}

check_updates() {
  if ! is_debian_like; then
    say "${YELLOW}[提示] 当前不是 Debian / Ubuntu 系列，跳过 apt 更新检查。${RESET}" \
        "${YELLOW}[Note] Not a Debian/Ubuntu system, skipping apt update check.${RESET}"
    return
  fi

  say "${GREEN}== 检查可用更新（apt） ==${RESET}" \
      "${GREEN}== Check available updates (apt) ==${RESET}"

  if ! apt update; then
    say "${YELLOW}[警告] apt update 失败，可能是网络或镜像源问题${RESET}" \
        "${YELLOW}[Warning] apt update failed, possibly network or mirror issue${RESET}"
    return 1
  fi
  echo
  say "可升级的软件包：" "Upgradable packages:"
  apt list --upgradable || true

  local ans
  ask "是否现在执行安全更新（apt upgrade -y）？[y/N]: " \
      "Run apt upgrade -y now? [y/N]: " ans
  case "$ans" in
    y|Y)
      if ! apt upgrade -y; then
        say "${YELLOW}[警告] apt upgrade 失败${RESET}" \
            "${YELLOW}[Warning] apt upgrade failed${RESET}"
        return 1
      fi
      say "${GREEN}[完成] 系统已执行升级。${RESET}" \
          "${GREEN}[Done] System upgraded.${RESET}"
      ;;
    *)
      say "${YELLOW}[跳过] 未执行升级。你可以稍后手动运行：sudo apt upgrade${RESET}" \
          "${YELLOW}[Skip] Upgrade not run. You can run later: sudo apt upgrade${RESET}"
      ;;
  esac
}

setup_unattended_upgrades() {
  if ! is_debian_like; then
    say "${YELLOW}[提示] 当前不是 Debian / Ubuntu 系列，跳过 unattended-upgrades 配置。${RESET}" \
        "${YELLOW}[Note] Not a Debian/Ubuntu system, skipping unattended-upgrades setup.${RESET}"
    return
  fi

  say "${GREEN}== 自动安全更新（unattended-upgrades）配置 ==${RESET}" \
      "${GREEN}== Setup automatic security updates (unattended-upgrades) ==${RESET}"

  if ! apt update; then
    say "${YELLOW}[警告] apt update 失败，可能是网络或镜像源问题${RESET}" \
        "${YELLOW}[Warning] apt update failed, possibly network or mirror issue${RESET}"
    return 1
  fi

  if ! apt install unattended-upgrades -y; then
    say "${YELLOW}[警告] unattended-upgrades 安装失败${RESET}" \
        "${YELLOW}[Warning] Failed to install unattended-upgrades${RESET}"
    return 1
  fi

  say "接下来会进入 dpkg-reconfigure 界面，请根据提示选择启用自动安全更新。" \
      "Now running dpkg-reconfigure; please enable automatic security updates in the dialog."
  dpkg-reconfigure unattended-upgrades

  say "${GREEN}[完成] unattended-upgrades 已安装并重新配置。${RESET}" \
      "${GREEN}[Done] unattended-upgrades installed and reconfigured.${RESET}"
}

# --- Swap 管理 ---
check_swap() {
  say "${GREEN}== Swap 状态检查 ==${RESET}" \
      "${GREEN}== Swap Status Check ==${RESET}"
  echo

  if swapon --show | grep -q .; then
    say "当前 Swap 配置：" "Current Swap configuration:"
    swapon --show
    echo
    local swap_total swap_used swap_pct
    swap_total=$(free -m | awk '/^Swap:/ {print $2}')
    swap_used=$(free -m | awk '/^Swap:/ {print $3}')
    if [ "$swap_total" -gt 0 ]; then
      swap_pct=$((swap_used * 100 / swap_total))
      say "Swap 使用率: ${swap_used}MB / ${swap_total}MB (${swap_pct}%)" \
          "Swap usage: ${swap_used}MB / ${swap_total}MB (${swap_pct}%)"
    fi
    echo
    local swappiness
    swappiness=$(cat /proc/sys/vm/swappiness)
    say "Swappiness 值: $swappiness (建议 10-30)" \
        "Swappiness value: $swappiness (recommended 10-30)"
  else
    say "${YELLOW}未检测到活动的 Swap${RESET}" \
        "${YELLOW}No active Swap detected${RESET}"
  fi
}

create_swap() {
  say "${GREEN}== 创建 Swap 文件 ==${RESET}" \
      "${GREEN}== Create Swap File ==${RESET}"
  echo

  # 检查是否已存在 Swap
  if swapon --show | grep -q .; then
    say "${YELLOW}已存在 Swap：${RESET}" "${YELLOW}Swap already exists:${RESET}"
    swapon --show
    echo
    local confirm
    ask "是否继续创建新的 Swap 文件？这将禁用现有 Swap [y/N]: " \
        "Continue creating new Swap file? This will disable existing Swap [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
      say "已取消" "Cancelled"
      return
    fi
    # 禁用现有 Swap
    swapoff -a 2>/dev/null || true
  fi

  # 计算推荐大小
  local mem_mb swap_size_mb swap_size_gb
  mem_mb=$(free -m | awk '/^Mem:/ {print $2}')

  if [ "$mem_mb" -le 2048 ]; then
    swap_size_mb=2048
  elif [ "$mem_mb" -le 4096 ]; then
    swap_size_mb=$mem_mb
  else
    swap_size_mb=4096  # 最大 4G
  fi
  swap_size_gb=$((swap_size_mb / 1024))

  say "系统内存: ${mem_mb}MB, 推荐 Swap 大小: ${swap_size_mb}MB (${swap_size_gb}G)" \
      "System RAM: ${mem_mb}MB, Recommended Swap size: ${swap_size_mb}MB (${swap_size_gb}G)"

  local custom_size
  ask "使用推荐大小？直接回车确认，或输入自定义大小(MB): " \
      "Use recommended size? Press Enter to confirm, or input custom size(MB): " custom_size

  if [ -n "$custom_size" ]; then
    if [[ "$custom_size" =~ ^[0-9]+$ ]] && [ "$custom_size" -ge 512 ]; then
      swap_size_mb=$custom_size
    else
      say "${RED}无效输入，使用推荐大小${RESET}" "${RED}Invalid input, using recommended size${RESET}"
    fi
  fi

  local swapfile="/swapfile"

  # 检查是否已存在 swapfile
  if [ -f "$swapfile" ]; then
    say "${YELLOW}$swapfile 已存在，将删除后重新创建${RESET}" \
        "${YELLOW}$swapfile already exists, will delete and recreate${RESET}"
    swapoff "$swapfile" 2>/dev/null || true
    rm -f "$swapfile"
  fi

  say "正在创建 ${swap_size_mb}MB Swap 文件..." \
      "Creating ${swap_size_mb}MB Swap file..."

  # 创建 Swap 文件
  if command -v fallocate &>/dev/null; then
    fallocate -l "${swap_size_mb}M" "$swapfile"
  else
    dd if=/dev/zero of="$swapfile" bs=1M count="$swap_size_mb" status=progress
  fi

  chmod 600 "$swapfile"
  mkswap "$swapfile"
  swapon "$swapfile"

  # 添加到 fstab（如果不存在）
  if ! grep -q "$swapfile" /etc/fstab; then
    echo "$swapfile none swap sw 0 0" >> /etc/fstab
    say "已添加到 /etc/fstab" "Added to /etc/fstab"
  fi

  # 设置 swappiness
  local current_swappiness
  current_swappiness=$(cat /proc/sys/vm/swappiness)
  if [ "$current_swappiness" -gt 30 ]; then
    sysctl vm.swappiness=10
    if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
      echo "vm.swappiness=10" >> /etc/sysctl.conf
    fi
    say "Swappiness 已设置为 10" "Swappiness set to 10"
  fi

  echo
  say "${GREEN}[完成] Swap 创建成功！${RESET}" \
      "${GREEN}[Done] Swap created successfully!${RESET}"
  swapon --show
}

remove_swap() {
  say "${GREEN}== 移除 Swap ==${RESET}" \
      "${GREEN}== Remove Swap ==${RESET}"
  echo

  if ! swapon --show | grep -q .; then
    say "${YELLOW}未检测到活动的 Swap${RESET}" \
        "${YELLOW}No active Swap detected${RESET}"
    return
  fi

  say "当前 Swap 配置：" "Current Swap configuration:"
  swapon --show
  echo

  local confirm
  ask "${RED}确定要移除所有 Swap 吗？[y/N]: ${RESET}" \
      "${RED}Are you sure you want to remove all Swap? [y/N]: ${RESET}" confirm

  if [[ ! "$confirm" =~ ^[yY]$ ]]; then
    say "已取消" "Cancelled"
    return
  fi

  # 禁用 Swap
  swapoff -a

  # 删除 swapfile（如果存在）
  if [ -f /swapfile ]; then
    rm -f /swapfile
    say "已删除 /swapfile" "Deleted /swapfile"
  fi

  # 从 fstab 移除 swap 条目
  if grep -q "swap" /etc/fstab; then
    sed -i '/swap/d' /etc/fstab
    say "已从 /etc/fstab 移除 swap 条目" "Removed swap entries from /etc/fstab"
  fi

  say "${GREEN}[完成] Swap 已移除${RESET}" \
      "${GREEN}[Done] Swap removed${RESET}"
}

manage_swap() {
  check_swap
  echo
  say "选择操作：" "Choose action:"
  say "  1) 创建/重建 Swap" "  1) Create/Rebuild Swap"
  say "  2) 移除 Swap" "  2) Remove Swap"
  say "  0) 返回" "  0) Return"
  echo

  local choice
  ask "请选择 [0-2]: " "Enter choice [0-2]: " choice

  case "$choice" in
    1) create_swap ;;
    2) remove_swap ;;
    0|*) return ;;
  esac
}

# --- 时间同步 ---
setup_chrony() {
  say "${GREEN}== 配置 Chrony 时间同步 ==${RESET}" \
      "${GREEN}== Setup Chrony Time Sync ==${RESET}"
  echo

  if ! is_debian_like; then
    say "${YELLOW}[提示] 当前不是 Debian / Ubuntu 系列${RESET}" \
        "${YELLOW}[Note] Not a Debian/Ubuntu system${RESET}"
    return
  fi

  # 安装 chrony
  if ! command -v chronyc &>/dev/null; then
    say "正在安装 chrony..." "Installing chrony..."
    apt update && apt install -y chrony
  else
    say "chrony 已安装" "chrony is already installed"
  fi

  # 启用服务
  systemctl enable chrony
  systemctl start chrony

  # 显示同步状态
  echo
  say "时间同步状态：" "Time sync status:"
  chronyc tracking
  echo
  chronyc sources

  say "${GREEN}[完成] Chrony 已配置${RESET}" \
      "${GREEN}[Done] Chrony configured${RESET}"
}

setup_timezone() {
  say "${GREEN}== 设置系统时区 ==${RESET}" \
      "${GREEN}== Set System Timezone ==${RESET}"
  echo

  local current_tz
  current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "Unknown")
  say "当前时区: $current_tz" "Current timezone: $current_tz"
  timedatectl status | head -5
  echo

  say "常用时区：" "Common timezones:"
  echo "  1) Asia/Shanghai (中国)"
  echo "  2) Asia/Hong_Kong"
  echo "  3) Asia/Tokyo"
  echo "  4) America/New_York"
  echo "  5) America/Los_Angeles"
  echo "  6) Europe/London"
  echo "  7) UTC"
  echo "  8) 手动输入 / Manual input"
  echo "  0) 取消 / Cancel"
  echo

  local choice new_tz
  ask "请选择 [0-8]: " "Enter choice [0-8]: " choice

  case "$choice" in
    1) new_tz="Asia/Shanghai" ;;
    2) new_tz="Asia/Hong_Kong" ;;
    3) new_tz="Asia/Tokyo" ;;
    4) new_tz="America/New_York" ;;
    5) new_tz="America/Los_Angeles" ;;
    6) new_tz="Europe/London" ;;
    7) new_tz="UTC" ;;
    8)
      ask "请输入时区（如 Asia/Shanghai）: " "Enter timezone (e.g., Asia/Shanghai): " new_tz
      # 验证时区
      if ! timedatectl list-timezones | grep -qx "$new_tz"; then
        say "${RED}无效时区: $new_tz${RESET}" "${RED}Invalid timezone: $new_tz${RESET}"
        return
      fi
      ;;
    0|*) return ;;
  esac

  if [ -n "$new_tz" ]; then
    timedatectl set-timezone "$new_tz"
    say "${GREEN}[完成] 时区已设置为 $new_tz${RESET}" \
        "${GREEN}[Done] Timezone set to $new_tz${RESET}"
    timedatectl status | head -3
  fi
}

# --- TCP BBR 拥塞控制 ---
check_bbr_status() {
  say "${GREEN}== TCP BBR 状态检查 ==${RESET}" \
      "${GREEN}== TCP BBR Status Check ==${RESET}"
  echo

  # 检查内核版本
  local kernel_version
  kernel_version=$(uname -r | cut -d'-' -f1)
  local kernel_major kernel_minor
  kernel_major=$(echo "$kernel_version" | cut -d'.' -f1)
  kernel_minor=$(echo "$kernel_version" | cut -d'.' -f2)

  say "${CYAN}[内核版本]${RESET}" "${CYAN}[Kernel Version]${RESET}"
  echo "  $(uname -r)"

  if [ "$kernel_major" -lt 4 ] || { [ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -lt 9 ]; }; then
    say "${YELLOW}[警告] BBR 需要内核 4.9+，当前内核不支持${RESET}" \
        "${YELLOW}[Warning] BBR requires kernel 4.9+, current kernel not supported${RESET}"
    return 1
  fi
  echo

  # 当前拥塞控制算法
  say "${CYAN}[当前拥塞控制算法]${RESET}" "${CYAN}[Current Congestion Control]${RESET}"
  local current_cc
  current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
  echo "  $current_cc"

  if [ "$current_cc" = "bbr" ]; then
    say "${GREEN}  ✓ BBR 已启用${RESET}" "${GREEN}  ✓ BBR is enabled${RESET}"
  else
    say "${YELLOW}  ✗ BBR 未启用${RESET}" "${YELLOW}  ✗ BBR is not enabled${RESET}"
  fi
  echo

  # 可用的拥塞控制算法
  say "${CYAN}[可用算法]${RESET}" "${CYAN}[Available Algorithms]${RESET}"
  local available_cc
  available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "unknown")
  echo "  $available_cc"
  echo

  # 队列调度器
  say "${CYAN}[队列调度器]${RESET}" "${CYAN}[Queue Discipline]${RESET}"
  local qdisc
  qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
  echo "  $qdisc"

  # BBR 模块加载状态
  echo
  say "${CYAN}[BBR 模块状态]${RESET}" "${CYAN}[BBR Module Status]${RESET}"
  if lsmod | grep -q tcp_bbr; then
    say "  ${GREEN}✓ tcp_bbr 模块已加载${RESET}" "${GREEN}  ✓ tcp_bbr module loaded${RESET}"
  else
    say "  ${YELLOW}✗ tcp_bbr 模块未加载${RESET}" "${YELLOW}  ✗ tcp_bbr module not loaded${RESET}"
  fi

  [ "$current_cc" = "bbr" ] && return 0 || return 1
}

enable_bbr() {
  say "${GREEN}== 启用 TCP BBR ==${RESET}" \
      "${GREEN}== Enable TCP BBR ==${RESET}"
  echo

  # 检查内核版本
  local kernel_version
  kernel_version=$(uname -r | cut -d'-' -f1)
  local kernel_major kernel_minor
  kernel_major=$(echo "$kernel_version" | cut -d'.' -f1)
  kernel_minor=$(echo "$kernel_version" | cut -d'.' -f2)

  if [ "$kernel_major" -lt 4 ] || { [ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -lt 9 ]; }; then
    say "${RED}[错误] BBR 需要内核 4.9+，当前内核 $(uname -r) 不支持${RESET}" \
        "${RED}[Error] BBR requires kernel 4.9+, current kernel $(uname -r) not supported${RESET}"
    return 1
  fi

  # 检查是否已启用
  local current_cc
  current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  if [ "$current_cc" = "bbr" ]; then
    say "${GREEN}[信息] BBR 已经启用，无需操作${RESET}" \
        "${GREEN}[Info] BBR is already enabled, no action needed${RESET}"
    return 0
  fi

  say "将进行以下配置：" "Will apply the following configuration:"
  echo "  1. net.core.default_qdisc = fq"
  echo "  2. net.ipv4.tcp_congestion_control = bbr"
  echo "  3. 写入 /etc/sysctl.d/99-bbr.conf (持久化)"
  echo

  local confirm
  ask "是否继续？[Y/n]: " "Continue? [Y/n]: " confirm
  if [[ "$confirm" =~ ^[nN]$ ]]; then
    say "已取消" "Cancelled"
    return
  fi

  # 写入配置文件
  cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
# TCP BBR Congestion Control
# Managed by vps-secure-tool
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

  # 立即应用
  sysctl -p /etc/sysctl.d/99-bbr.conf

  # 验证
  echo
  local new_cc
  new_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  if [ "$new_cc" = "bbr" ]; then
    say "${GREEN}[完成] TCP BBR 已成功启用${RESET}" \
        "${GREEN}[Done] TCP BBR enabled successfully${RESET}"
    echo
    say "当前状态：" "Current status:"
    echo "  拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
    echo "  队列调度: $(sysctl -n net.core.default_qdisc)"
  else
    say "${RED}[错误] BBR 启用失败${RESET}" "${RED}[Error] Failed to enable BBR${RESET}"
    return 1
  fi
}

manage_bbr() {
  say "${GREEN}== TCP BBR 管理 ==${RESET}" \
      "${GREEN}== TCP BBR Management ==${RESET}"
  echo

  check_bbr_status
  local bbr_enabled=$?
  echo

  if [ "$bbr_enabled" -eq 0 ]; then
    say "BBR 已启用，无需额外操作。" "BBR is already enabled, no action needed."
  else
    local confirm
    ask "是否启用 BBR？[y/N]: " "Enable BBR? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
      enable_bbr
    fi
  fi
}

# --- 内核安全参数优化 ---
show_sysctl_security() {
  say "${GREEN}== 内核安全参数状态 ==${RESET}" \
      "${GREEN}== Kernel Security Parameters ==${RESET}"
  echo

  # 定义要检查的参数及其安全推荐值
  local params=(
    "net.ipv4.ip_forward:0:IP 转发 (IP Forwarding)"
    "net.ipv4.conf.all.accept_redirects:0:接受 ICMP 重定向 (Accept ICMP Redirects)"
    "net.ipv4.conf.all.send_redirects:0:发送 ICMP 重定向 (Send ICMP Redirects)"
    "net.ipv4.conf.all.accept_source_route:0:接受源路由 (Accept Source Route)"
    "net.ipv4.conf.all.log_martians:1:记录异常包 (Log Martians)"
    "net.ipv4.icmp_echo_ignore_broadcasts:1:忽略广播 ICMP (Ignore Broadcast ICMP)"
    "net.ipv4.tcp_syncookies:1:SYN Cookie 保护 (SYN Cookie Protection)"
    "kernel.randomize_va_space:2:地址空间随机化 (ASLR)"
    "fs.protected_hardlinks:1:硬链接保护 (Hardlink Protection)"
    "fs.protected_symlinks:1:符号链接保护 (Symlink Protection)"
  )

  local pass_count=0
  local warn_count=0

  for param_info in "${params[@]}"; do
    local param_name param_safe param_desc
    param_name=$(echo "$param_info" | cut -d':' -f1)
    param_safe=$(echo "$param_info" | cut -d':' -f2)
    param_desc=$(echo "$param_info" | cut -d':' -f3)

    local current_val
    current_val=$(sysctl -n "$param_name" 2>/dev/null || echo "N/A")

    if [ "$current_val" = "$param_safe" ]; then
      echo -e "${GREEN}[PASS]${RESET} $param_desc"
      echo "        $param_name = $current_val"
      ((pass_count++))
    elif [ "$current_val" = "N/A" ]; then
      echo -e "${YELLOW}[N/A]${RESET}  $param_desc"
      echo "        $param_name = 不可用"
    else
      echo -e "${YELLOW}[WARN]${RESET} $param_desc"
      echo "        $param_name = $current_val (建议: $param_safe)"
      ((warn_count++))
    fi
  done

  echo
  say "统计: $pass_count 项符合安全标准, $warn_count 项建议优化" \
      "Summary: $pass_count passed, $warn_count need attention"
}

harden_sysctl() {
  say "${GREEN}== 应用内核安全加固 ==${RESET}" \
      "${GREEN}== Apply Kernel Security Hardening ==${RESET}"
  echo

  say "将创建 /etc/sysctl.d/99-vps-secure.conf 并应用以下安全参数：" \
      "Will create /etc/sysctl.d/99-vps-secure.conf with the following security parameters:"
  echo
  echo "  # 禁用 IP 转发（非路由器场景）"
  echo "  net.ipv4.ip_forward = 0"
  echo
  echo "  # 禁用 ICMP 重定向"
  echo "  net.ipv4.conf.all.accept_redirects = 0"
  echo "  net.ipv4.conf.all.send_redirects = 0"
  echo "  net.ipv4.conf.default.accept_redirects = 0"
  echo
  echo "  # 禁用源路由"
  echo "  net.ipv4.conf.all.accept_source_route = 0"
  echo "  net.ipv4.conf.default.accept_source_route = 0"
  echo
  echo "  # 启用异常包日志"
  echo "  net.ipv4.conf.all.log_martians = 1"
  echo
  echo "  # 忽略广播 ICMP"
  echo "  net.ipv4.icmp_echo_ignore_broadcasts = 1"
  echo
  echo "  # SYN Cookie 保护"
  echo "  net.ipv4.tcp_syncookies = 1"
  echo
  echo "  # 文件系统保护"
  echo "  fs.protected_hardlinks = 1"
  echo "  fs.protected_symlinks = 1"
  echo

  local confirm
  ask "是否应用这些安全参数？[y/N]: " "Apply these security parameters? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[yY]$ ]]; then
    say "已取消" "Cancelled"
    return
  fi

  # 写入配置文件
  local gen_time
  gen_time=$(date '+%Y-%m-%d %H:%M:%S')
  cat > /etc/sysctl.d/99-vps-secure.conf << EOF
# VPS Security Hardening - Kernel Parameters
# Managed by vps-secure-tool
# Generated: $gen_time

# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP broadcast
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable SYN cookie protection
net.ipv4.tcp_syncookies = 1

# Filesystem protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

  # 应用配置
  say "正在应用配置..." "Applying configuration..."
  if sysctl --system > /dev/null 2>&1; then
    say "${GREEN}[完成] 内核安全参数已应用${RESET}" \
        "${GREEN}[Done] Kernel security parameters applied${RESET}"
    echo
    say "配置文件: /etc/sysctl.d/99-vps-secure.conf" \
        "Config file: /etc/sysctl.d/99-vps-secure.conf"
  else
    say "${RED}[错误] 应用配置失败${RESET}" "${RED}[Error] Failed to apply configuration${RESET}"
    return 1
  fi
}

# ============================================================
# USER - 用户管理模块
# ============================================================

check_users_and_sudo() {
  say "${GREEN}== 用户与 sudo 权限检查 ==${RESET}" \
      "${GREEN}== Users & sudo privileges check ==${RESET}"

  if getent group sudo >/dev/null 2>&1; then
    say "sudo 组成员：" "Members of group 'sudo':"
    getent group sudo
  fi

  if getent group wheel >/dev/null 2>&1; then
    echo
    say "wheel 组成员：" "Members of group 'wheel':"
    getent group wheel
  fi

  echo
  say "当前登录用户与组：" "Current user and groups:"
  id
  echo

  say "sudoers 额外配置文件列表：" "Additional sudoers config files:"
  ls -l /etc/sudoers.d 2>/dev/null || say "无 /etc/sudoers.d 目录或无文件。" "No /etc/sudoers.d directory or files."

  echo
  say "请留意是否存在 NOPASSWD: ALL 等高危配置。" \
      "Please check if there are any high-risk rules like NOPASSWD: ALL."
}

create_user_secure() {
  say "${GREEN}== 新增安全 SSH 用户（支持仅密钥登录） ==${RESET}" \
      "${GREEN}== Create secure SSH user (key-only or password+key) ==${RESET}"

  local username
  ask "请输入要创建的用户名（仅小写字母/数字/下划线/短横线）： " \
      "Enter new username (lowercase letters/numbers/_/- only): " username

  if [ -z "$username" ]; then
    say "${RED}[错误] 用户名不能为空。${RESET}" \
        "${RED}[ERROR] Username cannot be empty.${RESET}"
    return
  fi

  if ! echo "$username" | grep -Eq '^[a-z_][a-z0-9_-]*$'; then
    say "${RED}[错误] 用户名格式不合法。${RESET}" \
        "${RED}[ERROR] Invalid username format.${RESET}"
    return
  fi

  if id -u "$username" >/dev/null 2>&1; then
    say "${RED}[错误] 用户已存在：$username${RESET}" \
        "${RED}[ERROR] User already exists: $username${RESET}"
    return
  fi

  local add_sudo login_mode sudo_pwd_set
  sudo_pwd_set="no"

  ask "是否将该用户加入 sudo 组？[y/N]: " \
      "Add this user to sudo group? [y/N]: " add_sudo

  say "请选择登录方式：" "Choose login method:"
  if [ "$LANG_MODE" = "zh" ]; then
    echo " 1) 仅允许 SSH 密钥登录（推荐，后续结合 PasswordAuthentication no 使用）"
    echo " 2) 允许密码登录（同时可配置 SSH 密钥）"
  else
    echo " 1) SSH key-only login (recommended, use together with PasswordAuthentication no)"
    echo " 2) Allow password login (and optionally SSH key)"
  fi

  ask "请输入选项编号 [1/2]（默认 1）: " \
      "Enter choice [1/2] (default 1): " login_mode
  [ -z "$login_mode" ] && login_mode="1"

  # 创建用户（初始禁用密码）
  adduser --disabled-password --gecos "" "$username"

  # 是否加入 sudo / wheel 组
  case "$add_sudo" in
    y|Y)
      if getent group sudo >/dev/null 2>&1; then
        usermod -aG sudo "$username"
      elif getent group wheel >/dev/null 2>&1; then
        usermod -aG wheel "$username"
      fi
      ;;
  esac

  # ========= 密码逻辑部分 =========
  # 1）如果选择允许密码登录（login_mode=2），设登录密码
  if [ "$login_mode" = "2" ]; then
    say "接下来为该用户设置密码：" \
        "Now set a password for this user:"
    passwd "$username"
  fi

  # 2）如果选择 key-only 且加入了 sudo 组，问要不要设一个 sudo 用的密码
  if [ "$login_mode" = "1" ] && [[ "$add_sudo" =~ ^[yY]$ ]]; then
    say "该用户已加入 sudo 组。为了使用 sudo，通常需要一个本地密码。" \
        "This user is in the sudo group. To use sudo, a local password is usually required."
    say "注意：后续如果你在 SSH 配置中关闭 PasswordAuthentication，该密码仅用于本地 sudo，不会被用于 SSH 远程密码登录。" \
        "Note: After you disable PasswordAuthentication in SSH config, this password will be used only for local sudo, not for SSH password logins."

    local set_sudo_pwd
    ask "是否现在为该用户设置 sudo 密码？[Y/n]: " \
        "Set a sudo password for this user now? [Y/n]: " set_sudo_pwd
    [ -z "$set_sudo_pwd" ] && set_sudo_pwd="Y"

    case "$set_sudo_pwd" in
      y|Y)
        say "接下来为该用户设置密码：" \
            "Now set a password for this user:"
        passwd "$username"
        sudo_pwd_set="yes"
        ;;
      *)
        say "${YELLOW}[提示] 你选择暂时不为该用户设置密码，sudo 将无法使用，除非之后手动运行：passwd $username${RESET}" \
            "${YELLOW}[Note] You chose not to set a password now; sudo will not be usable until you run: passwd $username${RESET}"
        ;;
    esac
  fi
  # ========= 密码逻辑结束 =========

  # 准备 .ssh 目录
  local home_dir auth_file
  home_dir=$(getent passwd "$username" | cut -d: -f6)
  chmod 755 "$home_dir"
  install -d -m 700 -o "$username" -g "$username" "$home_dir/.ssh"
  auth_file="$home_dir/.ssh/authorized_keys"
  touch "$auth_file"
  chown "$username:$username" "$auth_file"
  chmod 600 "$auth_file"

  # 选择添加 SSH 密钥方式
  say "是否现在为该用户添加 SSH 公钥？" \
      "Do you want to add an SSH public key for this user now?"
  if [ "$LANG_MODE" = "zh" ]; then
    echo " 1) 立即粘贴本地生成的公钥（推荐）"
    echo " 2) 在服务器上为该用户生成一对新的密钥（进阶用法）"
    echo " 3) 暂时跳过（稍后手动编辑 authorized_keys）"
  else
    echo " 1) Paste an existing public key (recommended)"
    echo " 2) Generate a new key pair on this server for this user (advanced)"
    echo " 3) Skip for now (edit authorized_keys later manually)"
  fi

  local key_choice
  ask "请输入选项编号 [1/2/3]（默认 1）: " \
      "Enter choice [1/2/3] (default 1): " key_choice
  [ -z "$key_choice" ] && key_choice="1"

  case "$key_choice" in
    1)
      say "请粘贴一行 SSH 公钥（例如以 ssh-ed25519 或 ssh-rsa 开头）：" \
          "Paste one line SSH public key (e.g. starting with ssh-ed25519 or ssh-rsa):"
      local pubkey
      read -r pubkey
      if [ -n "$pubkey" ]; then
        # 验证公钥格式
        if [[ "$pubkey" =~ ^ssh-(ed25519|rsa|ecdsa|dss)[[:space:]] ]] || [[ "$pubkey" =~ ^ecdsa-sha2-[[:alnum:]-]+[[:space:]] ]]; then
          echo "$pubkey" >> "$auth_file"
          say "${GREEN}[完成] 已写入 authorized_keys。${RESET}" \
              "${GREEN}[Done] Public key appended to authorized_keys.${RESET}"
        else
          say "${RED}[错误] 公钥格式无效，应以 ssh-ed25519、ssh-rsa、ssh-ecdsa 等开头。${RESET}" \
              "${RED}[ERROR] Invalid public key format. Should start with ssh-ed25519, ssh-rsa, ssh-ecdsa, etc.${RESET}"
        fi
      else
        say "${YELLOW}[提示] 未输入任何公钥，稍后可手动编辑 $auth_file。${RESET}" \
            "${YELLOW}[Note] No key entered. You can edit $auth_file later.${RESET}"
      fi
      ;;
    2)
      say "${YELLOW}[警告] 在服务器上生成密钥意味着私钥会暂存于服务器，请务必在下载后妥善删除。${RESET}" \
          "${YELLOW}[WARNING] Generating keys on the server means the private key is stored here. Download & delete it afterwards.${RESET}"
      local key_type key_path
      ask "选择密钥类型（默认 ed25519，可填 rsa/ed25519/ecdsa）: " \
          "Key type (default ed25519, or rsa/ed25519/ecdsa): " key_type
      # 验证密钥类型白名单
      case "$key_type" in
        ed25519|rsa|ecdsa) ;;
        *) key_type="ed25519" ;;
      esac
      key_path="$home_dir/.ssh/id_${key_type}"
      sudo -u "$username" ssh-keygen -t "$key_type" -f "$key_path" -N ""
      cat "${key_path}.pub" >> "$auth_file"
      say "${GREEN}[完成] 已为用户生成密钥对：${RESET}" \
          "${GREEN}[Done] Generated key pair for user:${RESET}"
      echo " Private key: $key_path"
      echo " Public key: ${key_path}.pub"
      say "你可以通过当前 SSH 会话查看并复制公钥/私钥内容，或用 scp 下载。" \
          "You can view/copy the key contents in this SSH session or download via scp."
      ;;
    3)
      say "${YELLOW}[提示] 未添加 SSH 公钥，用户目前只能依赖密码登录（如果已设置）。${RESET}" \
          "${YELLOW}[Note] No SSH key added. The user can only use password login (if configured).${RESET}"
      ;;
    *)
      ;;
  esac

  # key-only 模式下的最终处理
  if [ "$login_mode" = "1" ]; then
    # 如果没有为 sudo 设置密码，则继续锁定密码（完全 key-only，无 sudo 密码）
    if [ "$sudo_pwd_set" != "yes" ]; then
      passwd -l "$username" >/dev/null 2>&1 || true
    fi

    if [ "$sudo_pwd_set" = "yes" ]; then
      say "${GREEN}[完成] 已创建仅 SSH 密钥登录的用户（本地 sudo 使用密码）：$username${RESET}" \
          "${GREEN}[Done] Created key-only SSH user with local sudo password: $username${RESET}"
    else
      say "${GREEN}[完成] 已创建仅 SSH 密钥登录的用户：$username${RESET}" \
          "${GREEN}[Done] Created key-only login user: $username${RESET}"
    fi
  else
    say "${GREEN}[完成] 已创建允许密码登录的用户：$username${RESET}" \
        "${GREEN}[Done] Created user with password login: $username${RESET}"
  fi

  echo
  say "用户信息摘要：" "User summary:"
  id "$username"
  echo "Home: $home_dir"
  echo ".ssh: $home_dir/.ssh"
  echo "authorized_keys: $auth_file"
}

# 安全删除用户
delete_user_safe() {
  say "${GREEN}== 删除系统用户（带安全检查） ==${RESET}" \
      "${GREEN}== Delete system user (with safety checks) ==${RESET}"

  local username
  ask "请输入要删除的用户名： " \
      "Enter username to delete: " username

  if [ -z "$username" ]; then
    say "${RED}[错误] 用户名不能为空。${RESET}" \
        "${RED}[ERROR] Username cannot be empty.${RESET}"
    return
  fi

  if [ "$username" = "root" ] || [ "$username" = "$USER" ] || [ "$username" = "$SUDO_USER" ]; then
    say "${RED}[错误] 不允许删除 root 或当前登录用户：$username${RESET}" \
        "${RED}[ERROR] Refusing to delete root or current user: $username${RESET}"
    return
  fi

  if ! id -u "$username" >/dev/null 2>&1; then
    say "${RED}[错误] 用户不存在：$username${RESET}" \
        "${RED}[ERROR] User does not exist: $username${RESET}"
    return
  fi

  say "即将删除的用户信息：" "User info to be deleted:"
  id "$username"
  getent passwd "$username" || true
  echo

  if ps -u "$username" --no-headers 2>/dev/null | grep -q .; then
    say "${YELLOW}[提示] 该用户当前有正在运行的进程：${RESET}" \
        "${YELLOW}[Note] This user currently has running processes:${RESET}"
    ps -u "$username" || true
    echo
    say "建议先关闭这些进程或会话（例如：loginctl terminate-user $username）。" \
        "It is recommended to stop these processes/sessions first (e.g. loginctl terminate-user $username)."
    echo
  fi

  local del_home
  ask "是否同时删除该用户的 home 目录？[y/N]: " \
      "Also delete this user's home directory? [y/N]: " del_home

  local confirm
  ask "确认要删除用户 $username？此操作不可撤销。[y/N]: " \
      "Are you sure you want to delete user $username? This cannot be undone. [y/N]: " confirm

  case "$confirm" in
    y|Y)
      local del_success=false
      if [[ "$del_home" =~ ^[yY]$ ]]; then
        userdel -r "$username" && del_success=true || del_success=false
      else
        userdel "$username" && del_success=true || del_success=false
      fi
      if [ "$del_success" = "true" ]; then
        say "${GREEN}[完成] 用户 $username 已删除。${RESET}" \
            "${GREEN}[Done] User $username has been deleted.${RESET}"
      else
        say "${RED}[错误] 删除用户 $username 失败，请检查日志或手动执行 userdel。${RESET}" \
            "${RED}[ERROR] Failed to delete user $username. Please check logs or run userdel manually.${RESET}"
      fi
      ;;
    *)
      say "${YELLOW}[取消] 已取消删除用户操作。${RESET}" \
          "${YELLOW}[Canceled] User deletion aborted.${RESET}"
      ;;
  esac
}

lock_root_account() {
  say "${GREEN}== 锁定 root 账户密码（可选） ==${RESET}" \
      "${GREEN}== Lock root account password (optional) ==${RESET}"

  say "当前 root 密码状态（第二列为状态，L=锁定，P=有密码）：" \
      "Current root password status (2nd field: L=locked, P=has password):"
  passwd -S root || true
  echo

  local ans
  ask "是否锁定 root 密码？（不影响 sudo 提权，只影响直接使用 root 登录）[y/N]: " \
      "Lock root password? (does not affect sudo, only direct root login) [y/N]: " ans

  case "$ans" in
    y|Y)
      passwd -l root
      say "${GREEN}[完成] root 密码已锁定。${RESET}" \
          "${GREEN}[Done] root password locked.${RESET}"
      ;;
    *)
      say "${YELLOW}[跳过] 未更改 root 密码状态。${RESET}" \
          "${YELLOW}[Skip] Root password state unchanged.${RESET}"
      ;;
  esac
}

# ============================================================
# SSH - SSH配置模块
# ============================================================

check_ssh_config() {
  say "${GREEN}== SSH 配置检查 ==${RESET}" \
      "${GREEN}== SSH configuration check ==${RESET}"

  if [ ! -f /etc/ssh/sshd_config ]; then
    say "${RED}[错误] 未找到 /etc/ssh/sshd_config，可能不是常规 sshd。${RESET}" \
        "${RED}[ERROR] /etc/ssh/sshd_config not found, sshd may be non-standard.${RESET}"
    return
  fi

  say "[sshd_config 主文件前若干行]:" "[First lines of sshd_config]:"
  head -n 30 /etc/ssh/sshd_config
  echo

  if grep -qi "^Include" /etc/ssh/sshd_config; then
    say "检测到 Include 语句：" "Include directives detected:"
    grep -i "^Include" /etc/ssh/sshd_config
    echo
    say "/etc/ssh/sshd_config.d 目录内容：" "Contents of /etc/ssh/sshd_config.d:"
    ls -l /etc/ssh/sshd_config.d 2>/dev/null || say "无额外配置。" "No extra config files."
  fi

  echo
  say "sshd 最终生效配置（关键信息）：" "Effective sshd configuration (key fields):"
  if command -v sshd >/dev/null 2>&1; then
    sshd -T | grep -E "port|addressfamily|passwordauthentication|permitrootlogin|kbdinteractiveauthentication|challengeresponseauthentication|usepam|pubkeyauthentication" || true
  else
    say "未找到 sshd 命令，无法输出 -T 视图。" \
        "sshd not found, cannot run sshd -T."
  fi
}

harden_ssh_interactive() {
  say "${GREEN}== SSH 基础加固（禁 root / 禁密码） ==${RESET}" \
      "${GREEN}== SSH basic hardening (disable root / password auth) ==${RESET}"

  say "本步骤会：" "This step will:"
  say "  1) 禁止 root 通过 SSH 登录（PermitRootLogin no）" \
      "  1) Disable SSH login as root (PermitRootLogin no)"
  say "  2) 全局关闭 PasswordAuthentication（仅保留公钥登录）" \
      "  2) Set PasswordAuthentication no (public key only)"
  say "  3) 写入 /etc/ssh/sshd_config.d/99-local.conf 强制覆盖 PasswordAuthentication no" \
      "  3) Write /etc/ssh/sshd_config.d/99-local.conf to enforce PasswordAuthentication no"
  echo
  say "注意：" "Note:"
  say "  - 如需为 fallback 用户保留密码登录，应在此之后手动配置 Match User。" \
      "  - If you need a fallback user with password login, configure Match User manually afterwards."
  echo

  local ans
  ask "确认继续修改 SSH 配置？[y/N]: " \
      "Continue modifying SSH config? [y/N]: " ans
  case "$ans" in
    y|Y) ;;
    *)
      say "${YELLOW}[跳过] 未对 SSH 配置做任何变更。${RESET}" \
          "${YELLOW}[Skip] No changes made to SSH config.${RESET}"
      return
      ;;
  esac

  local sshd_main="/etc/ssh/sshd_config"
  local sshd_d_dir="/etc/ssh/sshd_config.d"

  mkdir -p "$sshd_d_dir"

  # 单文件备份（覆盖写入，避免累积）
  cp "$sshd_main" "${sshd_main}.bak"
  say "[备份] 已备份为 ${sshd_main}.bak" \
      "[Backup] Original sshd_config saved as ${sshd_main}.bak"

  # 辅助函数：幂等地设置 sshd 配置项
  # 先删除所有现有的同名配置（包括注释的），再添加新配置
  set_sshd_option() {
    local option="$1"
    local value="$2"
    local file="$3"
    # 删除所有包含该选项的行（注释或非注释）
    sed -ri "/^[[:space:]]*#?[[:space:]]*${option}[[:space:]]/d" "$file" 2>/dev/null || true
    # 然后在文件末尾添加新配置
    echo "${option} ${value}" >> "$file"
  }

  set_sshd_option "PermitRootLogin" "no" "$sshd_main"
  set_sshd_option "PasswordAuthentication" "no" "$sshd_main"
  set_sshd_option "ChallengeResponseAuthentication" "no" "$sshd_main"

  if ! grep -qi '^[[:space:]]*Include[[:space:]]\+/etc/ssh/sshd_config.d/\*' "$sshd_main"; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$sshd_main"
  fi

  local pa_conflicts
  pa_conflicts=$(grep -R "^[[:space:]]*PasswordAuthentication[[:space:]]\+yes" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true)
  if [ -n "$pa_conflicts" ]; then
    say "${YELLOW}[提示] 检测到以下 PasswordAuthentication yes 配置，将由 99-local.conf 覆盖：${RESET}" \
        "${YELLOW}[Note] Detected the following PasswordAuthentication yes entries; they will be overridden by 99-local.conf:${RESET}"
    echo "$pa_conflicts"
    echo
  fi

  local local_override="${sshd_d_dir}/99-local.conf"
  cat > "$local_override" <<'EOF'
# Local SSH auth overrides managed by vps_secure_tool.sh
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
EOF
  chmod 644 "$local_override"

  if command -v sshd >/dev/null 2>&1; then
    if sshd -t; then
      say "${GREEN}[校验通过] sshd 配置语法正确，准备重启 ssh 服务。${RESET}" \
          "${GREEN}[OK] sshd config syntax valid, restarting ssh service.${RESET}"
      systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || {
        say "${RED}[错误] 无法重启 ssh/sshd 服务，请手动检查。${RESET}" \
            "${RED}[ERROR] Failed to restart ssh/sshd, please check manually.${RESET}"
        return 1
      }
      say "${GREEN}[完成] ssh 服务已重启，请在新终端测试登录。${RESET}" \
          "${GREEN}[Done] ssh service restarted, please test login in a new terminal.${RESET}"
    else
      say "${RED}[错误] sshd -t 语法检测失败，已保留原备份文件，请手动排查。${RESET}" \
          "${RED}[ERROR] sshd -t syntax check failed, backup kept. Please fix manually.${RESET}"
    fi
  fi
}

change_ssh_port() {
  say "${GREEN}== 修改 SSH 端口（附带 UFW 规则） ==${RESET}" \
      "${GREEN}== Change SSH port (with UFW rule) ==${RESET}"

  say "当前 sshd 生效配置中的端口：" "Current sshd effective port:"
  if command -v sshd >/dev/null 2>&1; then
    sshd -T | grep -i '^port ' || true
  fi
  echo

  local newport
  ask "请输入新的 SSH 端口（1-65535，建议 2000-65000 之间，回车取消）: " \
      "Enter new SSH port (1-65535, recommended 2000-65000, Enter to cancel): " newport
  if [ -z "$newport" ]; then
    say "${YELLOW}[取消] 未修改 SSH 端口。${RESET}" \
        "${YELLOW}[Cancel] SSH port unchanged.${RESET}"
    return
  fi

  if ! echo "$newport" | grep -Eq '^[0-9]+$'; then
    say "${RED}[错误] 端口必须是数字。${RESET}" \
        "${RED}[ERROR] Port must be a number.${RESET}"
    return
  fi

  if [ "$newport" -lt 1 ] || [ "$newport" -gt 65535 ]; then
    say "${RED}[错误] 端口范围必须在 1-65535。${RESET}" \
        "${RED}[ERROR] Port must be in range 1-65535.${RESET}"
    return
  fi

  local sshd_main="/etc/ssh/sshd_config"
  cp "$sshd_main" "${sshd_main}.bak.port.$(date +%Y%m%d%H%M%S)"

  if grep -qi "^\s*Port " "$sshd_main"; then
    sed -ri "s/^\s*#?\s*Port .*/Port ${newport}/" "$sshd_main"
  else
    echo "Port ${newport}" >> "$sshd_main"
  fi

  if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
      say "${RED}[错误] sshd -t 语法检查失败，端口修改未生效，请还原备份。${RESET}" \
          "${RED}[ERROR] sshd -t failed, port change not applied. Please restore backup.${RESET}"
      return
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${newport}"/tcp || true
  fi

  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

  say "${GREEN}[完成] SSH 已配置为端口 ${newport}。请在新终端使用该端口测试登录。${RESET}" \
      "${GREEN}[Done] SSH configured to use port ${newport}. Please test login from a new terminal.${RESET}"

  if command -v ufw >/dev/null 2>&1; then
    local ans
    ask "确认新端口已经可以正常登录后，是否尝试删除旧的 22/tcp 规则？[y/N]: " \
        "After confirming new port works, remove old 22/tcp rule from UFW? [y/N]: " ans
    case "$ans" in
      y|Y)
        ufw delete allow 22/tcp || true
        say "${GREEN}[完成] 已尝试删除 22/tcp 的 UFW 规则。（若不存在则忽略）${RESET}" \
            "${GREEN}[Done] Attempted to delete UFW rule for 22/tcp (ignored if not present).${RESET}"
        ;;
      *)
        say "${YELLOW}[提示] 已保留 22/tcp 的 UFW 规则，请根据需要手动处理。${RESET}" \
            "${YELLOW}[Note] UFW rule for 22/tcp kept. Adjust manually as needed.${RESET}"
        ;;
    esac
  fi
}

# ============================================================
# FIREWALL - 防火墙模块
# ============================================================

firewall_check_and_setup() {
  say "${GREEN}== 防火墙检查与基础配置 (UFW) ==${RESET}" \
      "${GREEN}== Firewall check & basic setup (UFW) ==${RESET}"

  if ! command -v ufw >/dev/null 2>&1; then
    say "${YELLOW}[提示] 未检测到 ufw，将尝试安装（适用于 Debian / Ubuntu）。${RESET}" \
        "${YELLOW}[Note] UFW not found, will try to install (Debian/Ubuntu only).${RESET}"
    if is_debian_like; then
      apt update
      apt install ufw -y
    else
      say "${RED}[错误] 当前发行版不支持自动安装 ufw，请手动配置防火墙。${RESET}" \
          "${RED}[ERROR] This distro is not supported for automatic UFW install. Configure firewall manually.${RESET}"
      return
    fi
  fi

  say "[当前 UFW 状态]:" "[Current UFW status]:"
  ufw status verbose || true
  echo

  local ufw_active
  if ufw status | head -n1 | grep -iq "active"; then
    ufw_active="yes"
  else
    ufw_active="no"
  fi

  if [ "$ufw_active" = "yes" ]; then
    say "${GREEN}[信息] UFW 已启用。如果需要，你可以手动微调规则。${RESET}" \
        "${GREEN}[Info] UFW is already active. You can adjust rules manually if needed.${RESET}"
    return
  fi

  say "即将执行基础规则：" "Will apply basic rules:"
  say "  - allow OpenSSH (22/tcp 或当前 SSH 端口)" "  - allow OpenSSH (22/tcp or current SSH port)"
  say "  - allow 80/tcp, 443/tcp" "  - allow 80/tcp, 443/tcp"
  say "  - 默认 deny incoming, allow outgoing" \
      "  - default deny incoming, allow outgoing"
  echo

  local ans
  ask "确认应用上述 UFW 规则并启用防火墙？[y/N]: " \
      "Apply these UFW rules and enable firewall now? [y/N]: " ans
  case "$ans" in
    y|Y) ;;
    *)
      say "${YELLOW}[跳过] 未更改 UFW 规则。${RESET}" \
          "${YELLOW}[Skip] No UFW changes were made.${RESET}"
      return
      ;;
  esac

  ufw allow OpenSSH
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw default deny incoming
  ufw default allow outgoing
  ufw --force enable

  say "${GREEN}[完成] 当前 UFW 状态：${RESET}" \
      "${GREEN}[Done] Current UFW status:${RESET}"
  ufw status verbose
}

fail2ban_check_and_setup() {
  say "${GREEN}== fail2ban 检查与 sshd 防护配置 ==${RESET}" \
      "${GREEN}== fail2ban check & sshd protection setup ==${RESET}"

  if ! command -v fail2ban-client >/dev/null 2>&1; then
    say "${YELLOW}[提示] 未检测到 fail2ban，将尝试安装（Debian/Ubuntu）。${RESET}" \
        "${YELLOW}[Note] fail2ban not found, will try to install (Debian/Ubuntu).${RESET}"
    if is_debian_like; then
      apt update
      apt install fail2ban -y
    else
      say "${RED}[错误] 当前发行版不支持自动安装 fail2ban，请手动安装并配置。${RESET}" \
          "${RED}[ERROR] This distro is not supported for automatic fail2ban install. Configure manually.${RESET}"
      return
    fi
  fi

  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    say "[当前 fail2ban 状态]:" "[Current fail2ban status]:"
    fail2ban-client status || true
    echo
    if fail2ban-client status sshd >/dev/null 2>&1; then
      say "[sshd jail 状态]:" "[sshd jail status]:"
      fail2ban-client status sshd || true
      return
    fi
  fi

  local JAIL_LOCAL="/etc/fail2ban/jail.local"
  if [ -f "$JAIL_LOCAL" ]; then
    cp "$JAIL_LOCAL" "${JAIL_LOCAL}.bak.$(date +%Y%m%d%H%M%S)"
    say "[备份] 已备份现有 $JAIL_LOCAL" \
        "[Backup] Existing $JAIL_LOCAL has been saved."
  fi

  cat > "$JAIL_LOCAL" <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
banaction = ufw
backend = systemd

[sshd]
enabled = true
port    = ssh
filter  = sshd
# logpath 由 backend = systemd 自动处理
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban

  sleep 2

  if fail2ban-client status sshd >/dev/null 2>&1; then
    say "${GREEN}[完成] fail2ban 已启动，并配置 sshd 基础防护。${RESET}" \
        "${GREEN}[Done] fail2ban started with basic sshd protection.${RESET}"
    fail2ban-client status sshd || true
  else
    say "${RED}[错误] fail2ban 未能正确启动或 sshd jail 不存在，请手动排查。${RESET}" \
        "${RED}[ERROR] fail2ban failed to start or sshd jail missing, please check manually.${RESET}"
    systemctl status fail2ban --no-pager || true
  fi
}

# --- 端口快捷管理 ---
show_common_ports() {
  say "${CYAN}常用端口列表：${RESET}" "${CYAN}Common Ports:${RESET}"
  echo
  echo "  1) 22    - SSH"
  echo "  2) 80    - HTTP"
  echo "  3) 443   - HTTPS"
  echo "  4) 3306  - MySQL"
  echo "  5) 5432  - PostgreSQL"
  echo "  6) 6379  - Redis"
  echo "  7) 27017 - MongoDB"
  echo "  8) 8080  - HTTP Alt"
  echo "  9) 8443  - HTTPS Alt"
  echo "  0) 自定义端口 / Custom port"
}

quick_allow_port() {
  say "${GREEN}== 快捷放行端口 ==${RESET}" \
      "${GREEN}== Quick Allow Port ==${RESET}"
  echo

  if ! command -v ufw &>/dev/null; then
    say "${RED}[错误] UFW 未安装${RESET}" "${RED}[Error] UFW not installed${RESET}"
    return 1
  fi

  # 显示当前规则
  say "当前 UFW 规则：" "Current UFW rules:"
  ufw status numbered 2>/dev/null | head -20
  echo

  show_common_ports
  echo

  local choice
  if [ "$LANG_MODE" = "zh" ]; then
    read -rp "请选择端口 (1-9) 或输入 0 自定义: " choice
  else
    read -rp "Select port (1-9) or enter 0 for custom: " choice
  fi

  local port=""
  case "$choice" in
    1) port="22" ;;
    2) port="80" ;;
    3) port="443" ;;
    4) port="3306" ;;
    5) port="5432" ;;
    6) port="6379" ;;
    7) port="27017" ;;
    8) port="8080" ;;
    9) port="8443" ;;
    0)
      if [ "$LANG_MODE" = "zh" ]; then
        read -rp "请输入端口号 (1-65535): " port
      else
        read -rp "Enter port number (1-65535): " port
      fi
      ;;
    *)
      say "${YELLOW}无效选择${RESET}" "${YELLOW}Invalid choice${RESET}"
      return
      ;;
  esac

  # 验证端口号
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    say "${RED}[错误] 无效端口号: $port${RESET}" "${RED}[Error] Invalid port: $port${RESET}"
    return 1
  fi

  # 选择协议
  echo
  say "选择协议：" "Select protocol:"
  echo "  1) TCP"
  echo "  2) UDP"
  echo "  3) TCP + UDP"
  local proto_choice
  if [ "$LANG_MODE" = "zh" ]; then
    read -rp "请选择 [1]: " proto_choice
  else
    read -rp "Select [1]: " proto_choice
  fi
  proto_choice=${proto_choice:-1}

  local proto_arg=""
  case "$proto_choice" in
    1) proto_arg="/tcp" ;;
    2) proto_arg="/udp" ;;
    3) proto_arg="" ;;
    *) proto_arg="/tcp" ;;
  esac

  # 执行添加
  echo
  say "执行: ufw allow ${port}${proto_arg}" "Running: ufw allow ${port}${proto_arg}"
  if ufw allow "${port}${proto_arg}"; then
    say "${GREEN}[完成] 端口 ${port}${proto_arg} 已放行${RESET}" \
        "${GREEN}[Done] Port ${port}${proto_arg} allowed${RESET}"
  else
    say "${RED}[错误] 添加规则失败${RESET}" "${RED}[Error] Failed to add rule${RESET}"
    return 1
  fi
}

quick_deny_port() {
  say "${GREEN}== 快捷删除端口规则 ==${RESET}" \
      "${GREEN}== Quick Delete Port Rule ==${RESET}"
  echo

  if ! command -v ufw &>/dev/null; then
    say "${RED}[错误] UFW 未安装${RESET}" "${RED}[Error] UFW not installed${RESET}"
    return 1
  fi

  # 显示当前规则（带编号）
  say "当前 UFW 规则：" "Current UFW rules:"
  ufw status numbered
  echo

  say "${YELLOW}[提示] 输入规则编号可删除对应规则${RESET}" \
      "${YELLOW}[Note] Enter rule number to delete${RESET}"
  echo

  local rule_num
  if [ "$LANG_MODE" = "zh" ]; then
    read -rp "请输入要删除的规则编号 (留空取消): " rule_num
  else
    read -rp "Enter rule number to delete (empty to cancel): " rule_num
  fi

  if [ -z "$rule_num" ]; then
    say "已取消" "Cancelled"
    return
  fi

  # 验证是数字
  if ! [[ "$rule_num" =~ ^[0-9]+$ ]]; then
    say "${RED}[错误] 无效编号${RESET}" "${RED}[Error] Invalid number${RESET}"
    return 1
  fi

  # 确认删除
  local confirm
  ask "确认删除规则 #${rule_num}？[y/N]: " "Confirm delete rule #${rule_num}? [y/N]: " confirm
  if [[ ! "$confirm" =~ ^[yY]$ ]]; then
    say "已取消" "Cancelled"
    return
  fi

  # 执行删除（使用 yes 自动确认）
  if echo "y" | ufw delete "$rule_num"; then
    say "${GREEN}[完成] 规则 #${rule_num} 已删除${RESET}" \
        "${GREEN}[Done] Rule #${rule_num} deleted${RESET}"
  else
    say "${RED}[错误] 删除规则失败${RESET}" "${RED}[Error] Failed to delete rule${RESET}"
    return 1
  fi

  echo
  say "更新后的规则：" "Updated rules:"
  ufw status numbered
}

quick_port_management() {
  while true; do
    say "${GREEN}== 端口快捷管理 ==${RESET}" \
        "${GREEN}== Quick Port Management ==${RESET}"
    echo

    if [ "$LANG_MODE" = "zh" ]; then
      echo "  1) 放行端口"
      echo "  2) 删除规则"
      echo "  3) 查看当前规则"
      echo
      echo "  0) 返回"
    else
      echo "  1) Allow port"
      echo "  2) Delete rule"
      echo "  3) View current rules"
      echo
      echo "  0) Back"
    fi
    echo

    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请选择: " choice
    else
      read -rp "Select: " choice
    fi

    case "$choice" in
      1) quick_allow_port; pause ;;
      2) quick_deny_port; pause ;;
      3) ufw status numbered; pause ;;
      0) return ;;
      *)
        say "${YELLOW}无效选项${RESET}" "${YELLOW}Invalid choice${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# ============================================================
# LOG - 日志与排查模块
# ============================================================

show_listening_ports() {
  say "${GREEN}== 当前监听端口与进程 ==${RESET}" \
      "${GREEN}== Current listening ports & processes ==${RESET}"

  if command -v ss >/dev/null 2>&1; then
    ss -tulpen
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpen
  else
    say "未找到 ss 或 netstat 命令。" \
        "Neither ss nor netstat command found."
  fi
}

show_ssh_auth_logs() {
  say "${GREEN}== SSH 认证日志摘要 ==${RESET}" \
      "${GREEN}== SSH auth log summary ==${RESET}"

  local auth_log="/var/log/auth.log"
  if [ ! -f "$auth_log" ]; then
    say "未找到 $auth_log 文件（可能使用其他日志系统）。" \
        "$auth_log not found (system may use a different log setup)."
    return
  fi

  say "-- 最近 40 行 auth.log --" \
      "-- Last 40 lines of auth.log --"
  tail -n 40 "$auth_log" || true
  echo
  say "-- 最近 40 行包含 Failed password 的记录 --" \
      "-- Last 40 lines containing 'Failed password' --"
  if ! grep "Failed password" "$auth_log" | tail -n 40; then
    say "无匹配记录。" "No matching records."
  fi
}

show_cron_overview() {
  say "${GREEN}== 定时任务 (cron) 概览 ==${RESET}" \
      "${GREEN}== Cron jobs overview ==${RESET}"

  say "[root 用户 crontab]:" "[root user crontab]:"
  crontab -l 2>/dev/null || say "无 root crontab 或无法读取。" "No root crontab or cannot read."
  echo

  say "[系统级 crontab (/etc/crontab)]:" "[System crontab (/etc/crontab)]:"
  if [ -f /etc/crontab ]; then
    cat /etc/crontab
  else
    say "无 /etc/crontab 文件。" "/etc/crontab not found."
  fi
  echo

  say "[/etc/cron.* 目录列表]:" "[/etc/cron.* directories]:"
  ls -R /etc/cron* 2>/dev/null || say "无 /etc/cron* 目录。" "No /etc/cron* directories."
}

# --- 性能监控工具 ---
install_monitoring_tools() {
  say "${GREEN}== 安装监控工具 ==${RESET}" \
      "${GREEN}== Install Monitoring Tools ==${RESET}"
  echo

  if ! is_debian_like; then
    say "${YELLOW}[提示] 当前不是 Debian / Ubuntu 系列${RESET}" \
        "${YELLOW}[Note] Not a Debian/Ubuntu system${RESET}"
    return
  fi

  say "将安装以下工具：" "Will install the following tools:"
  echo "  - htop    (交互式进程查看器 / Interactive process viewer)"
  echo "  - iotop   (磁盘 I/O 监控 / Disk I/O monitor)"
  echo

  local confirm
  ask "是否继续？[Y/n]: " "Continue? [Y/n]: " confirm
  if [[ "$confirm" =~ ^[nN]$ ]]; then
    say "已取消" "Cancelled"
    return
  fi

  apt update
  apt install -y htop iotop

  say "${GREEN}[完成] 监控工具已安装${RESET}" \
      "${GREEN}[Done] Monitoring tools installed${RESET}"
  echo
  say "使用方法：" "Usage:"
  echo "  htop   - 交互式进程监控"
  echo "  iotop  - 磁盘 I/O 监控 (需要 root)"
}

show_system_overview() {
  say "${GREEN}== 系统状态概览 ==${RESET}" \
      "${GREEN}== System Status Overview ==${RESET}"
  echo

  # 系统信息
  say "${CYAN}[系统信息]${RESET}" "${CYAN}[System Info]${RESET}"
  echo "  主机名: $(hostname)"
  echo "  内核: $(uname -r)"
  echo "  运行时间: $(uptime -p 2>/dev/null || uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')"
  echo

  # 负载
  say "${CYAN}[系统负载]${RESET}" "${CYAN}[Load Average]${RESET}"
  local load1 load5 load15
  read -r load1 load5 load15 _ < /proc/loadavg
  local cpu_cores
  cpu_cores=$(nproc)
  echo "  1分钟: $load1 | 5分钟: $load5 | 15分钟: $load15"
  echo "  CPU 核心数: $cpu_cores"
  echo

  # CPU 使用率
  say "${CYAN}[CPU 使用率]${RESET}" "${CYAN}[CPU Usage]${RESET}"
  local cpu_idle cpu_used
  cpu_idle=$(top -bn1 | grep "Cpu(s)" | awk '{print $8}' | cut -d'%' -f1 2>/dev/null || echo "N/A")
  if [ "$cpu_idle" != "N/A" ]; then
    cpu_used=$(echo "100 - $cpu_idle" | bc 2>/dev/null || echo "N/A")
    echo "  使用率: ${cpu_used}%"
  else
    mpstat 1 1 2>/dev/null | tail -1 || echo "  无法获取 CPU 使用率"
  fi
  echo

  # 内存
  say "${CYAN}[内存使用]${RESET}" "${CYAN}[Memory Usage]${RESET}"
  free -h | head -2
  echo

  # Swap
  say "${CYAN}[Swap 使用]${RESET}" "${CYAN}[Swap Usage]${RESET}"
  if swapon --show | grep -q .; then
    free -h | grep -i swap
  else
    echo "  无 Swap"
  fi
  echo

  # 磁盘
  say "${CYAN}[磁盘使用]${RESET}" "${CYAN}[Disk Usage]${RESET}"
  df -h --output=source,size,used,avail,pcent,target | grep -E "^/dev|Filesystem" | head -10
  echo

  # 网络接口
  say "${CYAN}[网络接口]${RESET}" "${CYAN}[Network Interfaces]${RESET}"
  ip -br addr 2>/dev/null || ifconfig 2>/dev/null | grep -E "^[a-z]|inet " || echo "  无法获取网络信息"
  echo

  # 进程数
  say "${CYAN}[进程统计]${RESET}" "${CYAN}[Process Stats]${RESET}"
  echo "  运行进程数: $(ps aux | wc -l)"
  echo "  登录用户数: $(who | wc -l)"
}

launch_htop() {
  if command -v htop &>/dev/null; then
    htop
  else
    say "${YELLOW}htop 未安装${RESET}" "${YELLOW}htop not installed${RESET}"
    local confirm
    ask "是否现在安装？[y/N]: " "Install now? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
      apt update && apt install -y htop
      htop
    fi
  fi
}

# ============================================================
# AUDIT - 安全审计模块
# ============================================================

# 审计结果标记
_audit_pass() { echo -e "${GREEN}[PASS]${RESET} $1"; }
_audit_warn() { echo -e "${YELLOW}[WARN]${RESET} $1"; }
_audit_fail() { echo -e "${RED}[FAIL]${RESET} $1"; }
_audit_info() { echo -e "${CYAN}[INFO]${RESET} $1"; }

generate_audit_report() {
  say "${GREEN}== 安全审计报告 ==${RESET}" \
      "${GREEN}== Security Audit Report ==${RESET}"
  echo

  local report_file="/tmp/vps-audit-$(date +%Y%m%d-%H%M%S).txt"
  local pass_count=0 warn_count=0 fail_count=0

  # 开始收集报告内容（同时输出到终端和临时变量）
  {
    echo "=========================================="
    echo "  VPS 安全审计报告 / Security Audit Report"
    echo "  生成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  主机名: $(hostname)"
    echo "=========================================="
    echo

    # 1. 系统信息
    echo "=== 系统信息 ==="
    echo "  发行版: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "  内核版本: $(uname -r)"
    echo "  运行时间: $(uptime -p 2>/dev/null || uptime)"
    echo

    # 2. SSH 配置审计
    echo "=== SSH 配置审计 ==="

    # SSH 端口
    local ssh_port
    ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    [ -z "$ssh_port" ] && ssh_port="22"
    if [ "$ssh_port" = "22" ]; then
      _audit_warn "SSH 端口: $ssh_port (建议修改默认端口)"
      ((warn_count++))
    else
      _audit_pass "SSH 端口: $ssh_port (非默认端口)"
      ((pass_count++))
    fi

    # Root 登录
    local permit_root
    permit_root=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}')
    [ -z "$permit_root" ] && permit_root=$(grep -E "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$permit_root" = "no" ] || [ "$permit_root" = "prohibit-password" ]; then
      _audit_pass "Root 登录: $permit_root (已限制)"
      ((pass_count++))
    else
      _audit_fail "Root 登录: ${permit_root:-yes} (建议禁用)"
      ((fail_count++))
    fi

    # 密码认证
    local password_auth
    password_auth=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print $2}')
    [ -z "$password_auth" ] && password_auth=$(grep -E "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$password_auth" = "no" ]; then
      _audit_pass "密码认证: 已禁用 (仅密钥登录)"
      ((pass_count++))
    else
      _audit_warn "密码认证: ${password_auth:-yes} (建议使用密钥登录)"
      ((warn_count++))
    fi
    echo

    # 3. 防火墙状态
    echo "=== 防火墙状态 ==="
    if command -v ufw &>/dev/null; then
      local ufw_status
      ufw_status=$(ufw status 2>/dev/null | head -1)
      if echo "$ufw_status" | grep -q "active"; then
        _audit_pass "UFW: 已启用"
        ((pass_count++))
        ufw status numbered 2>/dev/null | head -15
      else
        _audit_fail "UFW: 未启用"
        ((fail_count++))
      fi
    else
      _audit_info "UFW: 未安装"
    fi
    echo

    # 4. Fail2ban 状态
    echo "=== Fail2ban 状态 ==="
    if command -v fail2ban-client &>/dev/null; then
      if systemctl is-active fail2ban &>/dev/null; then
        _audit_pass "Fail2ban: 运行中"
        ((pass_count++))
        local jails
        jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d '\t')
        _audit_info "活动监狱: $jails"
      else
        _audit_warn "Fail2ban: 已安装但未运行"
        ((warn_count++))
      fi
    else
      _audit_warn "Fail2ban: 未安装 (建议安装)"
      ((warn_count++))
    fi
    echo

    # 5. 用户审计
    echo "=== 用户审计 ==="
    # 检查空密码用户
    local empty_passwd
    empty_passwd=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | grep -v "^#" | head -5)
    if [ -n "$empty_passwd" ]; then
      _audit_fail "发现空密码或锁定账户: $empty_passwd"
      ((fail_count++))
    else
      _audit_pass "无空密码账户"
      ((pass_count++))
    fi

    # sudo 用户
    local sudo_users
    if getent group sudo &>/dev/null; then
      sudo_users=$(getent group sudo | cut -d: -f4)
      _audit_info "sudo 用户: $sudo_users"
    fi

    # UID 0 用户（除 root）
    local uid0_users
    uid0_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
    if [ -n "$uid0_users" ]; then
      _audit_fail "发现非 root 的 UID 0 用户: $uid0_users"
      ((fail_count++))
    else
      _audit_pass "无异常 UID 0 用户"
      ((pass_count++))
    fi
    echo

    # 6. 开放端口
    echo "=== 开放端口 (前 15 个) ==="
    if command -v ss &>/dev/null; then
      ss -tulnp 2>/dev/null | head -16
    elif command -v netstat &>/dev/null; then
      netstat -tulnp 2>/dev/null | head -16
    fi
    echo

    # 7. 登录审计
    echo "=== 最近登录 ==="
    _audit_info "最近成功登录 (前 5 条):"
    last -5 2>/dev/null | head -6
    echo
    _audit_info "最近失败登录尝试:"
    local fail_count_log
    fail_count_log=$(journalctl -u ssh --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0")
    if [ "$fail_count_log" -gt 100 ]; then
      _audit_warn "过去 24 小时失败登录: $fail_count_log 次 (异常高)"
    else
      _audit_info "过去 24 小时失败登录: $fail_count_log 次"
    fi
    echo

    # 8. 系统更新
    echo "=== 系统更新状态 ==="
    if command -v apt &>/dev/null; then
      local upgradable
      upgradable=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
      if [ "$upgradable" -gt 0 ]; then
        _audit_warn "有 $upgradable 个包可更新"
        ((warn_count++))
      else
        _audit_pass "系统已是最新"
        ((pass_count++))
      fi
    fi
    echo

    # 9. SUID 文件检查
    echo "=== SUID 文件检查 ==="
    local suid_count
    suid_count=$(find /usr -perm -4000 -type f 2>/dev/null | wc -l)
    _audit_info "系统 SUID 文件数量: $suid_count"
    echo

    # 汇总
    echo "=========================================="
    echo "  审计汇总 / Audit Summary"
    echo "  通过 (PASS): $pass_count"
    echo "  警告 (WARN): $warn_count"
    echo "  失败 (FAIL): $fail_count"
    echo "=========================================="

  } | tee "$report_file"

  echo
  say "${GREEN}报告已保存到: $report_file${RESET}" \
      "${GREEN}Report saved to: $report_file${RESET}"
}

check_suid_quick() {
  say "${GREEN}== SUID 程序快速检查（前 50 个） ==${RESET}" \
      "${GREEN}== Quick SUID binaries check (first 50) ==${RESET}"

  say "注意：这是一个只读列表，用于安全排查。不要随意删除系统 SUID 文件。" \
      "Note: This is a read-only list for security review. Do not remove SUID files blindly."
  echo
  find / -perm -4000 -type f 2>/dev/null | head -n 50
}

generate_snapshot() {
  local ts filename output_dir
  ts=$(date +%Y%m%d_%H%M%S)
  output_dir="$(pwd)"

  # 检查当前目录是否可写，否则使用 /tmp
  if [ ! -w "$output_dir" ]; then
    output_dir="/tmp"
    say "${YELLOW}[提示] 当前目录不可写，快照将保存到 /tmp${RESET}" \
        "${YELLOW}[Note] Current directory not writable, saving snapshot to /tmp${RESET}"
  fi

  filename="${output_dir}/vps_security_snapshot_${ts}.log"

  say "${GREEN}== 生成安全状态快照 ==${RESET}" \
      "${GREEN}== Generating security snapshot ==${RESET}"
  say "输出文件：$filename" "Output file: $filename"

  {
    echo "===== VPS Security Snapshot $ts ====="
    echo
    echo "--- Basic info ---"
    hostnamectl 2>/dev/null || hostname
    echo
    [ -f /etc/os-release ] && cat /etc/os-release
    echo
    echo "--- Kernel ---"
    uname -a
    echo
    echo "--- Listening ports (ss/netstat) ---"
    if command -v ss >/dev/null 2>&1; then
      ss -tulpen
    elif command -v netstat >/dev/null 2>&1; then
      netstat -tulpen
    else
      echo "No ss/netstat available."
    fi
    echo
    echo "--- UFW status ---"
    if command -v ufw >/dev/null 2>&1; then
      ufw status verbose
    else
      echo "UFW not installed."
    fi
    echo
    echo "--- fail2ban sshd status ---"
    if command -v fail2ban-client >/dev/null 2>&1; then
      fail2ban-client status sshd 2>/dev/null || fail2ban-client status 2>/dev/null || echo "sshd jail not found."
    else
      echo "fail2ban not installed."
    fi
    echo
    echo "--- SSH effective config (sshd -T key fields) ---"
    if command -v sshd >/dev/null 2>&1; then
      sshd -T | grep -E "port|addressfamily|passwordauthentication|permitrootlogin|pubkeyauthentication|kbdinteractiveauthentication|challengeresponseauthentication|usepam" || true
    else
      echo "sshd binary not found."
    fi
    echo
    echo "--- SSH auth log (tail) ---"
    if [ -f /var/log/auth.log ]; then
      tail -n 80 /var/log/auth.log
    else
      echo "/var/log/auth.log not found."
    fi
    echo
    echo "--- SUID binaries (first 50) ---"
    find / -perm -4000 -type f 2>/dev/null | head -n 50
    echo
    echo "--- Root crontab ---"
    crontab -l 2>/dev/null || echo "No root crontab."
    echo
    echo "--- /etc/crontab ---"
    if [ -f /etc/crontab ]; then
      cat /etc/crontab
    else
      echo "/etc/crontab not found."
    fi
    echo
    echo "===== END OF SNAPSHOT ====="
  } > "$filename"

  if [ -f "$filename" ]; then
    say "${GREEN}[完成] 已生成快照：$filename${RESET}" \
        "${GREEN}[Done] Snapshot saved to: $filename${RESET}"
  else
    say "${RED}[错误] 快照生成失败。${RESET}" \
        "${RED}[ERROR] Failed to create snapshot file.${RESET}"
  fi
}

# ============================================================
# UPDATE - 自更新模块
# ============================================================

# 比较版本号（返回: 0=相等, 1=v1>v2, 2=v1<v2）
version_compare() {
  local v1="$1" v2="$2"
  if [ "$v1" = "$v2" ]; then
    return 0
  fi
  local IFS=.
  local i v1_parts=($v1) v2_parts=($v2)
  for ((i=0; i<${#v1_parts[@]} || i<${#v2_parts[@]}; i++)); do
    local p1="${v1_parts[i]:-0}"
    local p2="${v2_parts[i]:-0}"
    if ((p1 > p2)); then
      return 1
    elif ((p1 < p2)); then
      return 2
    fi
  done
  return 0
}

# 检查更新
check_update() {
  say "${GREEN}== 检查脚本更新 ==${RESET}" \
      "${GREEN}== Checking for updates ==${RESET}"

  say "当前版本: $VERSION" "Current version: $VERSION"

  local remote_version
  remote_version=$(curl -sS --connect-timeout 10 "https://raw.githubusercontent.com/${GITHUB_REPO}/main/VERSION" 2>/dev/null | tr -d '[:space:]')

  if [ -z "$remote_version" ]; then
    say "${YELLOW}[提示] 无法获取远程版本信息，请检查网络连接。${RESET}" \
        "${YELLOW}[Note] Could not fetch remote version. Please check network.${RESET}"
    return 1
  fi

  say "远程版本: $remote_version" "Remote version: $remote_version"

  version_compare "$VERSION" "$remote_version"
  local cmp_result=$?

  if [ $cmp_result -eq 2 ]; then
    say "${CYAN}[发现新版本] 可更新到 $remote_version${RESET}" \
        "${CYAN}[New version available] Can update to $remote_version${RESET}"
    return 0
  elif [ $cmp_result -eq 0 ]; then
    say "${GREEN}[已是最新] 当前已是最新版本。${RESET}" \
        "${GREEN}[Up to date] You are running the latest version.${RESET}"
    return 1
  else
    say "${GREEN}[开发版本] 当前版本高于发布版本。${RESET}" \
        "${GREEN}[Development] Current version is ahead of release.${RESET}"
    return 1
  fi
}

# 执行更新
do_update() {
  say "${GREEN}== 更新脚本 ==${RESET}" \
      "${GREEN}== Updating script ==${RESET}"

  # 获取当前脚本路径
  local script_path
  script_path="$(readlink -f "$0")"

  # 备份当前脚本
  local backup_path="${script_path}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$script_path" "$backup_path"
  say "[备份] 已备份当前脚本到: $backup_path" \
      "[Backup] Current script backed up to: $backup_path"

  # 下载新版本
  local download_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/vps_secure_tool.sh"
  local tmp_file="/tmp/vps_secure_tool_update.sh"

  say "正在下载新版本..." "Downloading new version..."
  if ! curl -sS --connect-timeout 30 -o "$tmp_file" "$download_url"; then
    say "${RED}[错误] 下载失败，保留当前版本。${RESET}" \
        "${RED}[ERROR] Download failed. Keeping current version.${RESET}"
    return 1
  fi

  # 基本验证：检查文件是否为有效的 bash 脚本
  if ! head -n1 "$tmp_file" | grep -q "^#!/"; then
    say "${RED}[错误] 下载的文件无效，保留当前版本。${RESET}" \
        "${RED}[ERROR] Downloaded file is invalid. Keeping current version.${RESET}"
    rm -f "$tmp_file"
    return 1
  fi

  # 替换脚本
  mv "$tmp_file" "$script_path"
  chmod +x "$script_path"

  say "${GREEN}[完成] 更新成功！${RESET}" \
      "${GREEN}[Done] Update successful!${RESET}"
  say "新版本将在下次运行时生效，或使用以下命令重新启动：" \
      "New version will take effect on next run, or restart with:"
  echo "  exec $script_path"

  local restart_now
  ask "是否现在重启脚本？[y/N]: " "Restart script now? [y/N]: " restart_now
  if [[ "$restart_now" =~ ^[yY]$ ]]; then
    exec "$script_path"
  fi
}

# 显示版本信息
show_version() {
  say "${GREEN}== 版本信息 ==${RESET}" \
      "${GREEN}== Version Info ==${RESET}"
  echo
  echo "  $SCRIPT_NAME v$VERSION"
  echo "  GitHub: https://github.com/${GITHUB_REPO}"
  echo
  say "更新日志请查看: https://github.com/${GITHUB_REPO}/blob/main/CHANGELOG.md" \
      "Changelog: https://github.com/${GITHUB_REPO}/blob/main/CHANGELOG.md"
}

# ============================================================
# MENU - 菜单系统（主菜单 + 子菜单）
# ============================================================

# --- 子菜单：系统初始化 ---
menu_init() {
  while true; do
    print_header
    if [ "$LANG_MODE" = "zh" ]; then
      echo "  [系统初始化]"
      echo
      echo "  1) 显示系统基础信息"
      echo "  2) 显示资源使用情况（内存/磁盘/进程）"
      echo "  3) 检查系统更新（apt）并可选升级"
      echo "  4) 配置自动安全更新（unattended-upgrades）"
      echo "  5) Swap 管理（查看/创建/删除）"
      echo "  6) 配置时间同步（chrony）"
      echo "  7) 设置系统时区"
      echo "  8) TCP BBR 网络优化"
      echo "  9) 内核安全参数检查"
      echo "  10) 应用内核安全加固"
      echo
      echo "  0) 返回主菜单"
    else
      echo "  [System Init]"
      echo
      echo "  1) Show basic system info"
      echo "  2) Show resource usage (memory/disk/processes)"
      echo "  3) Check updates (apt) and optionally upgrade"
      echo "  4) Setup automatic security updates (unattended-upgrades)"
      echo "  5) Swap management (view/create/remove)"
      echo "  6) Setup time sync (chrony)"
      echo "  7) Set system timezone"
      echo "  8) TCP BBR network optimization"
      echo "  9) Kernel security parameters check"
      echo "  10) Apply kernel security hardening"
      echo
      echo "  0) Back to main menu"
    fi
    echo
    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请输入选项编号: " choice
    else
      read -rp "Enter choice: " choice
    fi
    echo
    case "$choice" in
      1) show_basic_info; pause ;;
      2) show_resource_usage; pause ;;
      3) check_updates; pause ;;
      4) setup_unattended_upgrades; pause ;;
      5) manage_swap; pause ;;
      6) setup_chrony; pause ;;
      7) setup_timezone; pause ;;
      8) manage_bbr; pause ;;
      9) show_sysctl_security; pause ;;
      10) harden_sysctl; pause ;;
      0) return ;;
      *)
        say "${YELLOW}无效选项${RESET}" "${YELLOW}Invalid choice${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# --- 子菜单：用户与SSH管理 ---
menu_user_ssh() {
  while true; do
    print_header
    if [ "$LANG_MODE" = "zh" ]; then
      echo "  [用户与SSH管理]"
      echo
      echo "  1) 新增安全用户（仅密钥或密码+密钥）"
      echo "  2) 删除系统用户（带安全检查）"
      echo "  3) 检查用户与 sudo 权限"
      echo "  4) 检查 SSH 配置（含 sshd -T）"
      echo "  5) SSH 基础加固（禁 root / 禁密码）"
      echo "  6) 修改 SSH 端口（附带 UFW 规则）"
      echo "  7) 锁定 root 账户密码"
      echo
      echo "  0) 返回主菜单"
    else
      echo "  [User & SSH Management]"
      echo
      echo "  1) Create secure user (key-only or password+key)"
      echo "  2) Delete system user (with safety checks)"
      echo "  3) Check users and sudo privileges"
      echo "  4) Check SSH configuration (including sshd -T)"
      echo "  5) SSH basic hardening (disable root/password)"
      echo "  6) Change SSH port (with UFW rule)"
      echo "  7) Lock root account password"
      echo
      echo "  0) Back to main menu"
    fi
    echo
    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请输入选项编号: " choice
    else
      read -rp "Enter choice: " choice
    fi
    echo
    case "$choice" in
      1) create_user_secure; pause ;;
      2) delete_user_safe; pause ;;
      3) check_users_and_sudo; pause ;;
      4) check_ssh_config; pause ;;
      5) harden_ssh_interactive; pause ;;
      6) change_ssh_port; pause ;;
      7) lock_root_account; pause ;;
      0) return ;;
      *)
        say "${YELLOW}无效选项${RESET}" "${YELLOW}Invalid choice${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# --- 子菜单：防火墙与安全 ---
menu_firewall() {
  while true; do
    print_header
    if [ "$LANG_MODE" = "zh" ]; then
      echo "  [防火墙与安全]"
      echo
      echo "  1) 检查并配置 UFW 防火墙 (22/80/443)"
      echo "  2) 检查并配置 fail2ban sshd 防护"
      echo "  3) 端口快捷管理（放行/删除规则）"
      echo
      echo "  0) 返回主菜单"
    else
      echo "  [Firewall & Security]"
      echo
      echo "  1) Check & setup UFW firewall (22/80/443)"
      echo "  2) Check & configure fail2ban sshd jail"
      echo "  3) Quick port management (allow/delete rules)"
      echo
      echo "  0) Back to main menu"
    fi
    echo
    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请输入选项编号: " choice
    else
      read -rp "Enter choice: " choice
    fi
    echo
    case "$choice" in
      1) firewall_check_and_setup; pause ;;
      2) fail2ban_check_and_setup; pause ;;
      3) quick_port_management ;;
      0) return ;;
      *)
        say "${YELLOW}无效选项${RESET}" "${YELLOW}Invalid choice${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# --- 子菜单：日志与排查 ---
menu_log() {
  while true; do
    print_header
    if [ "$LANG_MODE" = "zh" ]; then
      echo "  [日志与排查]"
      echo
      echo "  1) 查看当前监听端口与进程"
      echo "  2) 查看 SSH 认证日志摘要"
      echo "  3) 查看 cron 定时任务概览"
      echo "  4) 系统状态概览（CPU/内存/磁盘）"
      echo "  5) 安装监控工具（htop/iotop）"
      echo "  6) 启动 htop"
      echo
      echo "  0) 返回主菜单"
    else
      echo "  [Logs & Troubleshooting]"
      echo
      echo "  1) Show listening ports & processes"
      echo "  2) Show SSH auth log summary"
      echo "  3) Show cron jobs overview"
      echo "  4) System status overview (CPU/Memory/Disk)"
      echo "  5) Install monitoring tools (htop/iotop)"
      echo "  6) Launch htop"
      echo
      echo "  0) Back to main menu"
    fi
    echo
    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请输入选项编号: " choice
    else
      read -rp "Enter choice: " choice
    fi
    echo
    case "$choice" in
      1) show_listening_ports; pause ;;
      2) show_ssh_auth_logs; pause ;;
      3) show_cron_overview; pause ;;
      4) show_system_overview; pause ;;
      5) install_monitoring_tools; pause ;;
      6) launch_htop ;;
      0) return ;;
      *)
        say "${YELLOW}无效选项${RESET}" "${YELLOW}Invalid choice${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# --- 子菜单：安全审计 ---
menu_audit() {
  while true; do
    print_header
    if [ "$LANG_MODE" = "zh" ]; then
      echo "  [安全审计]"
      echo
      echo "  1) 快速检查 SUID 程序（前 50 个）"
      echo "  2) 生成安全状态快照"
      echo "  3) 生成安全审计报告（综合检查）"
      echo
      echo "  0) 返回主菜单"
    else
      echo "  [Security Audit]"
      echo
      echo "  1) Quick SUID binaries check (first 50)"
      echo "  2) Generate security snapshot"
      echo "  3) Generate security audit report (comprehensive)"
      echo
      echo "  0) Back to main menu"
    fi
    echo
    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请输入选项编号: " choice
    else
      read -rp "Enter choice: " choice
    fi
    echo
    case "$choice" in
      1) check_suid_quick; pause ;;
      2) generate_snapshot; pause ;;
      3) generate_audit_report; pause ;;
      0) return ;;
      *)
        say "${YELLOW}无效选项${RESET}" "${YELLOW}Invalid choice${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# --- 子菜单：配置管理 ---
menu_config() {
  while true; do
    print_header
    if [ "$LANG_MODE" = "zh" ]; then
      echo "  [配置管理]"
      echo
      echo "  1) 查看当前配置"
      echo "  2) 编辑配置文件"
      echo "  3) 备份安全配置"
      echo "  4) 恢复安全配置"
      echo "  5) 查看可用备份"
      echo
      echo "  0) 返回主菜单"
    else
      echo "  [Configuration]"
      echo
      echo "  1) Show current configuration"
      echo "  2) Edit configuration file"
      echo "  3) Backup security configuration"
      echo "  4) Restore security configuration"
      echo "  5) List available backups"
      echo
      echo "  0) Back to main menu"
    fi
    echo
    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请输入选项编号: " choice
    else
      read -rp "Enter choice: " choice
    fi
    echo
    case "$choice" in
      1) show_config; pause ;;
      2) edit_config; pause ;;
      3) backup_config; pause ;;
      4) restore_config; pause ;;
      5) list_backups; pause ;;
      0) return ;;
      *)
        say "${YELLOW}无效选项${RESET}" "${YELLOW}Invalid choice${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# --- 子菜单：更新与关于 ---
menu_update() {
  while true; do
    print_header
    if [ "$LANG_MODE" = "zh" ]; then
      echo "  [更新与关于]"
      echo
      echo "  1) 检查脚本更新"
      echo "  2) 更新到最新版本"
      echo "  3) 显示版本信息"
      echo
      echo "  0) 返回主菜单"
    else
      echo "  [Update & About]"
      echo
      echo "  1) Check for script updates"
      echo "  2) Update to latest version"
      echo "  3) Show version info"
      echo
      echo "  0) Back to main menu"
    fi
    echo
    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请输入选项编号: " choice
    else
      read -rp "Enter choice: " choice
    fi
    echo
    case "$choice" in
      1) check_update; pause ;;
      2)
        if check_update; then
          local do_upd
          ask "是否现在更新？[y/N]: " "Update now? [y/N]: " do_upd
          if [[ "$do_upd" =~ ^[yY]$ ]]; then
            do_update
          fi
        fi
        pause
        ;;
      3) show_version; pause ;;
      0) return ;;
      *)
        say "${YELLOW}无效选项${RESET}" "${YELLOW}Invalid choice${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# --- 主菜单 ---
show_main_menu() {
  print_header
  if [ "$LANG_MODE" = "zh" ]; then
    echo "当前版本: v$VERSION | 语言: 中文"
    echo
    echo "  1) 系统初始化"
    echo "  2) 用户与SSH管理"
    echo "  3) 防火墙与安全"
    echo "  4) 日志与排查"
    echo "  5) 安全审计"
    echo "  6) 配置管理"
    echo "  7) 更新与关于"
    echo
    echo "  L) 切换语言 (中/英)"
    echo "  0) 退出"
  else
    echo "Version: v$VERSION | Language: English"
    echo
    echo "  1) System Init"
    echo "  2) User & SSH Management"
    echo "  3) Firewall & Security"
    echo "  4) Logs & Troubleshooting"
    echo "  5) Security Audit"
    echo "  6) Configuration"
    echo "  7) Update & About"
    echo
    echo "  L) Switch language (zh/en)"
    echo "  0) Exit"
  fi
  echo
}

main_loop() {
  while true; do
    show_main_menu
    local choice
    if [ "$LANG_MODE" = "zh" ]; then
      read -rp "请输入选项编号: " choice
    else
      read -rp "Enter choice: " choice
    fi
    echo
    case "$choice" in
      1) menu_init ;;
      2) menu_user_ssh ;;
      3) menu_firewall ;;
      4) menu_log ;;
      5) menu_audit ;;
      6) menu_config ;;
      7) menu_update ;;
      [lL]) toggle_lang ;;
      0)
        echo "Bye~"
        exit 0
        ;;
      *)
        say "${YELLOW}无效选项，请重新输入。${RESET}" \
            "${YELLOW}Invalid choice, please try again.${RESET}"
        sleep 1
        ;;
    esac
    clear
  done
}

# ============================================================
# MAIN - 主入口
# ============================================================

need_root
check_distro
load_config
main_loop
