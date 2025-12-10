# vps-secure-tools · VPS 运维 + 安全加固工具箱

[English Version / 英文版](./README-en.md)

一个面向个人开发者的 **VPS（Virtual Private Server 虚拟专用服务器） 运维 + 安全加固工具箱**。  
通过交互式菜单，帮你完成常见的服务器安全与日常运维动作，而不用死记硬背命令。

---

## 🧩 功能概览

> 首次出现的缩写会同时给出全称。

主要功能：

- 新建安全 SSH（Secure Shell 安全外壳协议）用户  
  - 仅密钥登录 / 密码 + 密钥登录  
  - 自动创建 `~/.ssh/authorized_keys`，权限正确
- 禁用 root 远程登录、关闭密码登录（只保留公钥登录）
- 检查与配置 UFW（Uncomplicated Firewall 简易防火墙）规则
- 安装并配置 fail2ban（暴力破解防护工具），自动封禁异常 IP
- 检查当前 SSH 配置、防火墙、登录日志、SUID（Set-User-ID 置用户 ID 位）程序、定时任务
- 一键生成安全状态快照日志，方便做「学习记录 / 审计留档」

目标：**上 VPS 之后只要记得先跑这个脚本，剩下的都用菜单点一遍。**

---

## ⚡ 一条命令安装与运行（快速方式）

> ⚠️ 说明：这是典型的 `curl | bash` 用法，适合你自己使用。  
> 出于安全考虑，**第一次使用时建议先看一眼源码**（见下一节）。


```bash
curl -fsSL https://raw.githubusercontent.com/IsaacZhaoo/vps-secure-tool/main/vps_secure_tool.sh | sudo bash
```

---

## ✅ 更安全的安装方式（推荐）

第一次使用时，建议采用「下载 → 查看 → 再执行」的流程：

```bash
# 1. 下载脚本
curl -fsSL https://raw.githubusercontent.com/IsaacZhaoo/vps-secure-tool/main/vps_secure_tool.sh -o vps_secure_tool.sh

# 2. 查看脚本内容（任选其一）
less vps_secure_tool.sh
# 或
nano vps_secure_tool.sh

# 3. 赋予执行权限
chmod +x vps_secure_tool.sh

# 4. 以 root / sudo 运行
sudo ./vps_secure_tool.sh
```

> 🔒 小提示：  
> 运行过程中请始终保留当前 SSH 会话（终端窗口）不要关，  
> 确认新的登录方式（例如新用户 + 密钥登录）测试成功后，再退出旧会话。

---

## 🖥️ 适用环境

- 操作系统：  
  - 推荐：Debian / Ubuntu 系列发行版  
  - 其他 Linux 发行版上，部分功能（例如 `apt` / `ufw` / `unattended-upgrades`）可能不可用
- 权限要求：  
  - 必须以 `root` 或具备 `sudo` 权限的用户运行
- 依赖：  
  - 必需：`bash`、`sshd`（OpenSSH 服务器）、常见系统工具（`ip`、`ss` 或 `netstat`、`free`、`df`、`ps` 等）  
  - 可选：`ufw`、`fail2ban`（在 Debian / Ubuntu 上可由脚本自动安装）

---

## 📋 菜单功能详解

脚本启动后，会显示一个中英双语菜单，按数字选择操作即可。

### 菜单功能（简要说明）

1. 切换语言（中文 / English）  
2. 显示系统基础信息（主机名、发行版、内核、网络接口与 IP）  
3. 显示系统资源使用情况（内存 / 磁盘 / Top 进程）  
4. 检查系统更新（`apt`）并可选执行 `apt upgrade`  
5. 配置自动安全更新（`unattended-upgrades`）  
6. 新增安全 SSH 用户  
   - 仅密钥登录（推荐）或密码 + 密钥登录  
   - 自动创建 `.ssh` 目录与 `authorized_keys`，校正权限  
   - 可选择加入 `sudo` / `wheel` 组  
   - 支持粘贴现有公钥，或在服务器上生成新的密钥对（附安全提醒）  
7. 检查用户与 `sudo` 权限（`sudo` / `wheel` 组、`/etc/sudoers.d`）  
8. 检查 SSH 配置（含 `sshd -T` 关键字段）  
9. SSH 基础加固：  
   - `PermitRootLogin no`（禁止 root 用户远程 SSH 登录）  
   - `PasswordAuthentication no`（关闭密码登录，只允许公钥）  
   - 自动备份配置、语法校验、重启 `ssh` / `sshd`  
10. 修改 SSH 端口（并自动在 UFW 中放行新端口）  
11. 检查防火墙状态（UFW / firewalld）  
12. 一键配置 UFW 基础规则：允许 OpenSSH / 80 / 443，其他入站默认拒绝  
13. 检查 fail2ban 状态（包括 `sshd` jail）  
14. 安装并配置 fail2ban sshd 防护  
15. 查看当前监听端口与进程（`ss -tulpen` / `netstat -tulpen`）  
16. 查看 SSH 认证日志摘要（`/var/log/auth.log` + “Failed password” 记录）  
17. 查看定时任务（cron）概览：root crontab / `/etc/crontab` / `/etc/cron*`  
18. 快速检查 SUID 程序（前 50 个），辅助安全排查  
19. 生成一次安全状态快照日志（保存到当前目录）  
20. 锁定 root 账户密码（不影响 `sudo` 提权，仅禁止直接使用 root 密码登录）  
0. 退出脚本  

---

## 🔄 推荐使用流程（示例）

适合「新 VPS 上线时」的一种典型流程：

1. 在本地生成 SSH 密钥对，并确保可以使用非 root 用户 + 密钥登录 VPS。  
2. 在 VPS 上运行本脚本：  
   - 先用默认 root 或临时账户登录；  
   - 使用菜单：  
     - `6`：创建一个仅密钥登录的运维用户（加入 sudo 组）；  
     - （可选）`10`：将 SSH 端口改为非 22；  
     - `9`：禁用 root SSH 登录，禁用密码登录（只保留公钥登录）；  
     - `12`：启用 UFW，并只放行 SSH / 80 / 443；  
     - `14`：安装并开启 fail2ban。  
   - 再开一个新终端，用新用户 + 密钥登录测试，确认一切正常。  
3. 使用：  
   - `15` / `16` / `18`：进行日常安全自查；  
   - `19`：生成安全快照，把日志文件归档到你的「服务器学习记录」里。  

---

## ⚠️ 风险提示

- 本脚本会修改与安全强相关的配置（尤其是 SSH、UFW、防火墙、fail2ban 等），使用前请务必：  
  - 确保至少有一个可用的 SSH 密钥登录入口；  
  - 操作期间不要关闭当前 SSH 会话；  
  - 在新会话中验证新配置（例如新用户或新端口）能正常登录后，再关闭旧会话。  
- 作者不对因使用本脚本导致的任何直接或间接损失负责，请在理解相关风险后再使用。  

---

## 📜 许可证（License）

本项目使用 **MIT License（麻省理工学院开源许可证）**。

你可以自由地复制、修改、分发本脚本，但请保留许可证声明。
