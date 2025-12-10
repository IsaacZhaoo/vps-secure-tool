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
#   - 尽量以“检查 + 交互确认”的方式进行变更，避免直接搞崩 SSH。
#   - 主要支持 Debian/Ubuntu + ufw + fail2ban 的常见组合。
#   - 一些功能（如添加用户）需要你在交互过程中输入用户名/密码。

set -e

# 颜色输出
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

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

# 通用输出函数：根据 LANG_MODE 在中英文之间切换
say() {
  local zh="$1"
  local en="$2"
  if [ "$LANG_MODE" = "zh" ]; then
    echo -e "$zh"
  else
    echo -e "$en"
  fi
}

# 通用输入提示函数：中英文提示
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
  apt update
  echo
  say "可升级的软件包：" "Upgradable packages:"
  apt list --upgradable || true

  local ans
  ask "是否现在执行安全更新（apt upgrade -y）？[y/N]: " \
      "Run apt upgrade -y now? [y/N]: " ans
  case "$ans" in
    y|Y)
      apt upgrade -y
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
  apt update
  apt install unattended-upgrades -y

  say "接下来会进入 dpkg-reconfigure 界面，请根据提示选择启用自动安全更新。" \
      "Now running dpkg-reconfigure; please enable automatic security updates in the dialog."
  dpkg-reconfigure unattended-upgrades

  say "${GREEN}[完成] unattended-upgrades 已安装并重新配置。${RESET}" \
      "${GREEN}[Done] unattended-upgrades installed and reconfigured.${RESET}"
}

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
    home_dir=$(eval echo "~$username")
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
                echo "$pubkey" >> "$auth_file"
                say "${GREEN}[完成] 已写入 authorized_keys。${RESET}" \
                    "${GREEN}[Done] Public key appended to authorized_keys.${RESET}"
            else
                say "${YELLOW}[提示] 未输入任何公钥，稍后可手动编辑 $auth_file。${RESET}" \
                    "${YELLOW}[Note] No key entered. You can edit $auth_file later.${RESET}"
            fi
            ;;
        2)
            say "${YELLOW}[警告] 在服务器上生成密钥意味着私钥会暂存于服务器，请务必在下载后妥善删除。${RESET}" \
                "${YELLOW}[WARNING] Generating keys on the server means the private key is stored here. Download & delete it afterwards.${RESET}"
            local key_type key_path
            ask "选择密钥类型（默认 ed25519，可填 rsa/ed25519）: " \
                "Key type (default ed25519, or rsa/ed25519): " key_type
            [ -z "$key_type" ] && key_type="ed25519"
            key_path="$home_dir/.ssh/id_${key_type}"
            sudo -u "$username" ssh-keygen -t "$key_type" -f "$key_path" -N ""
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

# 新增：安全删除用户功能
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

    # 禁止删除 root 和当前登录用户
    if [ "$username" = "root" ] || [ "$username" = "$USER" ]; then
        say "${RED}[错误] 不允许删除 root 或当前登录用户：$username${RESET}" \
            "${RED}[ERROR] Refusing to delete root or current user: $username${RESET}"
        return
    fi

    # 检查用户是否存在
    if ! id -u "$username" >/dev/null 2>&1; then
        say "${RED}[错误] 用户不存在：$username${RESET}" \
            "${RED}[ERROR] User does not exist: $username${RESET}"
        return
    fi

    say "即将删除的用户信息：" "User info to be deleted:"
    id "$username"
    getent passwd "$username" || true
    echo

    # 检查是否有进程
    if ps -u "$username" >/dev/null 2>&1; then
        say "${YELLOW}[提示] 该用户当前有正在运行的进程：${RESET}" \
            "${YELLOW}[Note] This user currently has running processes:${RESET}"
        ps -u "$username" || true
        echo
        say "建议先关闭这些进程或会话（例如：loginctl terminate-user $username）。" \
            "It is recommended to stop these processes/sessions first (e.g. loginctl terminate-user $username)."
        echo
    fi

    # 是否删除 home 目录
    local del_home
    ask "是否同时删除该用户的 home 目录？[y/N]: " \
        "Also delete this user's home directory? [y/N]: " del_home

    # 最终确认
    local confirm
    ask "确认要删除用户 $username？此操作不可撤销。[y/N]: " \
        "Are you sure you want to delete user $username? This cannot be undone. [y/N]: " confirm

    case "$confirm" in
        y|Y)
            if [[ "$del_home" =~ ^[yY]$ ]]; then
                userdel -r "$username"
            else
                userdel "$username"
            fi

            if [ $? -eq 0 ]; then
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
    sshd -T | egrep "port|addressfamily|passwordauthentication|permitrootlogin|kbdinteractiveauthentication|challengeresponseauthentication|usepam|pubkeyauthentication" || true
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

  cp "$sshd_main" "${sshd_main}.bak.$(date +%Y%m%d%H%M%S)"
  say "[备份] 已备份为 ${sshd_main}.bak.<timestamp>" \
      "[Backup] Original sshd_config saved as ${sshd_main}.bak.<timestamp>"

  # 使用 sed 修改或追加配置
  if grep -qi "^\s*PermitRootLogin" "$sshd_main"; then
    sed -ri 's/^\s*#?\s*PermitRootLogin.*/PermitRootLogin no/' "$sshd_main"
  else
    echo "PermitRootLogin no" >> "$sshd_main"
  fi

  if grep -qi "^\s*PasswordAuthentication" "$sshd_main"; then
    sed -ri 's/^\s*#?\s*PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_main"
  else
    echo "PasswordAuthentication no" >> "$sshd_main"
  fi

  # 可选：关闭 ChallengeResponseAuthentication
  if grep -qi "^\s*ChallengeResponseAuthentication" "$sshd_main"; then
    sed -ri 's/^\s*#?\s*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$sshd_main"
  else
    echo "ChallengeResponseAuthentication no" >> "$sshd_main"
  fi

  # 确保包含 .d 目录
  if ! grep -qi '^[[:space:]]*Include[[:space:]]\+/etc/ssh/sshd_config.d/\*' "$sshd_main"; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$sshd_main"
  fi

  # 提示可能存在 PasswordAuthentication yes 的文件
  local pa_conflicts
  pa_conflicts=$(grep -R "^[[:space:]]*PasswordAuthentication[[:space:]]\+yes" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true)
  if [ -n "$pa_conflicts" ]; then
    say "${YELLOW}[提示] 检测到以下 PasswordAuthentication yes 配置，将由 99-local.conf 覆盖：${RESET}" \
        "${YELLOW}[Note] Detected the following PasswordAuthentication yes entries; they will be overridden by 99-local.conf:${RESET}"
    echo "$pa_conflicts"
    echo
  fi

  # 写入 99-local.conf 强制覆盖
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

  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.port.$(date +%Y%m%d%H%M%S)

  if grep -qi "^\s*Port " /etc/ssh/sshd_config; then
    sed -ri "s/^\s*#?\s*Port .*/Port ${newport}/" /etc/ssh/sshd_config
  else
    echo "Port ${newport}" >> /etc/ssh/sshd_config
  fi

  if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t; then
      say "${RED}[错误] sshd -t 语法检查失败，端口修改未生效，请还原备份。${RESET}" \
          "${RED}[ERROR] sshd -t failed, port change not applied. Please restore backup.${RESET}"
      return
    fi
  fi

  # 防火墙放行新端口
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

# 合并：防火墙检查 + 一键基础规则
check_firewall() {
  say "${GREEN}== 防火墙 UFW 检查与基础配置 ==${RESET}" \
      "${GREEN}== Firewall (UFW) check & basic setup ==${RESET}"

  if command -v ufw >/dev/null 2>&1; then
    say "[当前 UFW 状态]:" "[Current UFW status]:"
    ufw status verbose || true
  else
    say "未检测到 ufw。" "UFW not found."
  fi

  if command -v firewall-cmd >/dev/null 2>&1; then
    echo
    say "[firewalld 状态]:" "[firewalld status]:"
    firewall-cmd --state 2>/dev/null || true
    firewall-cmd --list-all 2>/dev/null || true
  fi

  # UFW 检查 + 如未启用则一键基础规则
  if ! command -v ufw >/dev/null 2>&1; then
    if is_debian_like; then
      local ans
      ask "检测到系统未安装 ufw，是否现在安装并配置基础规则？[y/N]: " \
          "UFW is not installed. Install and apply basic rules now? [y/N]: " ans
      case "$ans" in
        y|Y)
          apt update
          apt install -y ufw
          ;;
        *)
          say "${YELLOW}[跳过] 未安装 ufw。${RESET}" \
              "${YELLOW}[Skip] UFW not installed.${RESET}"
          return
          ;;
      esac
    else
      say "${YELLOW}[提示] 当前发行版不支持自动安装 ufw，请手动配置防火墙。${RESET}" \
          "${YELLOW}[Note] This distro is not supported for automatic UFW install; configure firewall manually.${RESET}"
      return
    fi
  fi

  # 再次获取 UFW 状态
  local status_line
  status_line=$(ufw status 2>/dev/null | head -n 1 || true)
  if echo "$status_line" | grep -qi "Status: active"; then
    say "${GREEN}[通过] UFW 已启用。上方已显示当前规则。如需修改，可手动调整或重新运行本选项。${RESET}" \
        "${GREEN}[OK] UFW is already active. Current rules are shown above. Adjust manually as needed.${RESET}"
    return
  fi

  local ans2
  ask "检测到 UFW 未启用，是否应用基础规则（SSH/80/443 + 默认 deny incoming）并启用？[y/N]: " \
      "UFW is inactive. Apply basic rules (SSH/80/443 + default deny incoming) and enable now? [y/N]: " ans2
  case "$ans2" in
    y|Y)
      basic_firewall_setup_ufw
      ;;
    *)
      say "${YELLOW}[跳过] 未对 UFW 做任何更改。${RESET}" \
          "${YELLOW}[Skip] UFW was not modified.${RESET}"
      ;;
  esac
}

basic_firewall_setup_ufw() {
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

  say "${GREEN}== UFW 基础规则配置 ==${RESET}" \
      "${GREEN}== UFW basic rules setup ==${RESET}"
  say "即将执行：" "Will apply:"
  say "  - allow OpenSSH (22/tcp 或当前 SSH 端口)" "  - allow OpenSSH (22/tcp or current SSH port)"
  say "  - allow 80/tcp, 443/tcp" "  - allow 80/tcp, 443/tcp"
  say "  - 默认 deny incoming, allow outgoing" \
      "  - default deny incoming, allow outgoing"
  echo

  local ans
  ask "确认应用上述 UFW 规则？[y/N]: " \
      "Apply these UFW rules now? [y/N]: " ans
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
  ufw enable

  say "${GREEN}[完成] 当前 UFW 状态：${RESET}" \
      "${GREEN}[Done] Current UFW status:${RESET}"
  ufw status verbose
}

# fail2ban 启动帮助函数（带等待）
start_fail2ban_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  systemctl enable fail2ban 2>/dev/null || true
  systemctl restart fail2ban 2>/dev/null || systemctl start fail2ban 2>/dev/null || true

  local i
  for i in $(seq 1 10); do
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
      return 0
    fi
    sleep 1
  done

  return 1
}

setup_fail2ban_basic() {
  say "${GREEN}== fail2ban 基础安装与 sshd 防护配置 ==${RESET}" \
      "${GREEN}== fail2ban basic install & sshd protection ==${RESET}"
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    if is_debian_like; then
      apt update
      apt in
