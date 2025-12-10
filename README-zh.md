# vps-secure-tool · VPS 运维 + 安全加固工具箱

[English Version / 英文版](./README-en.md)

一个面向个人开发者的 **VPS（Virtual Private Server 虚拟专用服务器） 运维 + 安全加固工具箱**。  
通过交互式菜单，帮你完成常见的服务器安全与日常运维动作，而不用死记硬背命令。

---

## 🧩 功能概览

> 首次出现的缩写会同时给出全称。

### 系统初始化与优化
- Swap 内存管理（自动计算推荐大小、创建/删除）
- 时间同步（chrony）与时区设置
- TCP BBR 拥塞控制优化（显著提升网络性能）
- 内核安全参数加固（sysctl 自动配置）

### 用户与 SSH（Secure Shell 安全外壳协议）安全
- 新建安全 SSH 用户（仅密钥登录 / 密码 + 密钥登录）
- 自动创建 `~/.ssh/authorized_keys`，权限正确
- 禁用 root 远程登录、关闭密码登录（只保留公钥登录）
- 修改 SSH 端口（自动同步 UFW 规则）

### 防火墙与防护
- 检查与配置 UFW（Uncomplicated Firewall 简易防火墙）规则
- **常用端口快捷放行**（HTTP/HTTPS/MySQL/PostgreSQL/Redis/MongoDB 等 9 种）
- 安装并配置 fail2ban（暴力破解防护工具），自动封禁异常 IP

### 监控与审计
- 查看系统信息、资源使用（CPU/内存/磁盘/负载）
- 检查当前 SSH 配置、防火墙状态、登录日志
- SUID（Set-User-ID 置用户 ID 位）程序检查、定时任务查看
- **生成安全审计报告**（含 [PASS]/[WARN]/[FAIL] 标记）
- 一键生成安全状态快照日志

### 配置管理
- 配置文件支持（`/etc/vps-secure-tool.conf`）
- **配置备份与恢复**（SSH/UFW/fail2ban/sysctl 一键打包）
- 脚本自动更新检测与升级

目标：**上 VPS 之后只要记得先跑这个脚本，剩下的都用菜单点一遍。**

---

## ⚡ 一条命令安装与运行（快速方式）

> ⚠️ 说明：这是典型的 `curl | bash` 用法，适合你自己使用。  
> 出于安全考虑，**第一次使用时建议先看一眼源码**（见下一节）。


```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/IsaacZhaoo/vps-secure-tool/main/vps_secure_tool.sh)"
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

### 主菜单结构

脚本采用分类子菜单设计，主菜单包含 7 个功能分类：

1. **系统环境初始化** - 基础信息、资源监控、更新、Swap、时间同步、BBR、内核加固
2. **用户与 SSH 管理** - 创建用户、SSH 配置、端口修改、安全加固
3. **防火墙管理** - UFW 配置、fail2ban、端口快捷管理
4. **日志与监控** - 监听端口、登录日志、定时任务、系统监控工具
5. **安全审计** - SUID 检查、安全快照、审计报告生成
6. **配置管理** - 查看/编辑配置、备份/恢复配置
7. **更新与关于** - 检查更新、执行更新、版本信息

### 主要功能说明

**系统初始化**
- Swap 管理：自动计算推荐大小（内存≤2G用2G，>2G用等量，最大4G）
- TCP BBR：一键启用 BBR 拥塞控制算法，提升网络性能
- 内核安全参数：禁用 IP 转发、ICMP 重定向，启用 ASLR 等 10+ 项加固

**防火墙管理**
- 端口快捷管理：支持 9 种常用端口一键放行/关闭
  - SSH(22), HTTP(80), HTTPS(443), MySQL(3306), PostgreSQL(5432)
  - Redis(6379), MongoDB(27017), Alt-HTTP(8080), Alt-HTTPS(8443)

**安全审计**
- 审计报告：自动检查 SSH、防火墙、用户权限等，生成 [PASS]/[WARN]/[FAIL] 标记报告

**配置管理**
- 备份：打包 SSH/UFW/fail2ban/sysctl 配置到 `/var/backups/vps-secure-tool/`
- 恢复：从备份文件还原配置，可选重启相关服务  

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
