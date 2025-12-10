# vps-secure-tool

一个面向个人开发者的 **VPS（Virtual Private Server 虚拟专用服务器） 运维 + 安全加固工具箱**。  
通过交互式菜单，帮你完成常见的服务器安全与日常运维操作，不用死记硬背命令。

> An ops & security toolbox for VPS (Virtual Private Server), with an interactive menu so you do not need to memorize commands.

- 🇨🇳 [中文详细说明书](./README-zh.md)
- 🇬🇧 [English detailed documentation](./README-en.md)

---

## 🚀 一条命令快速使用（Quick Start）

> ⚠️ 第一次使用建议先查看脚本源码，确认无误后再长期使用。  
> ⚠️ For first-time use, please review the script source before trusting it.

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/IsaacZhaoo/vps-secure-tool/main/vps_secure_tool.sh)"
```

---

## ✅ 更安全的用法（推荐）

```bash
# 1. 下载脚本
curl -fsSL https://raw.githubusercontent.com/IsaacZhaoo/vps-secure-tool/main/vps_secure_tool.sh -o vps_secure_tool.sh

# 2. 看一眼脚本内容（任选一种）
less vps_secure_tool.sh
# 或
nano vps_secure_tool.sh

# 3. 赋予执行权限
chmod +x vps_secure_tool.sh

# 4. 以 root / sudo 运行
sudo ./vps_secure_tool.sh
```

> 小提示：操作期间请保留当前 SSH 会话，在新终端测试新的登录方式成功后，再关闭旧会话，避免把自己锁在门外。

---

## 🧩 它大概能做什么？（What it does）

**系统初始化与优化**
- Swap 内存管理（自动计算大小、创建/删除）
- 时间同步（chrony）与时区设置
- TCP BBR 拥塞控制优化
- 内核安全参数加固（sysctl）

**用户与 SSH 安全**
- 新建安全 SSH 用户（仅密钥登录 / 密码 + 密钥登录）
- 禁用 root SSH 登录、关闭密码登录（只保留公钥登录）
- 修改 SSH 端口

**防火墙与防护**
- 检查并配置 UFW 防火墙规则
- 常用端口快捷放行（HTTP/HTTPS/MySQL/PostgreSQL/Redis 等）
- 安装并配置 fail2ban，抵御 SSH 暴力破解

**监控与审计**
- 查看系统信息、资源使用、SSH 配置、防火墙状态
- 登录日志分析、SUID 程序检查、定时任务查看
- 生成安全审计报告（含 PASS/WARN/FAIL 标记）
- 一键生成安全状态快照日志

**配置管理**
- 配置文件支持（/etc/vps-secure-tool.conf）
- 配置备份与恢复（SSH/UFW/fail2ban/sysctl）
- 脚本自动更新检测

运行脚本后，按照菜单编号一步步操作即可。

---

## 🖥️ 适用环境

- 推荐：Debian / Ubuntu 系列发行版  
- 需要：`root` 或具有 `sudo` 权限的用户  
- 依赖：`bash`、`sshd`、常见系统工具（`ip`、`ss` 或 `netstat`、`free`、`df`、`ps` 等）  
- `ufw` / `fail2ban` 可在 Debian / Ubuntu 上由脚本自动安装

---

## ⚠️ 风险提示（Disclaimer）

本脚本会修改 SSH、防火墙、fail2ban 等安全相关配置。使用前请确保：

- 已经配置好至少一个可用的 SSH 密钥登录；
- 在修改配置时保留当前 SSH 会话；
- 在新终端验证新的登录方式可用后，再退出旧会话。

作者不对因使用本脚本导致的任何直接或间接损失负责，请在理解相关风险后再使用。

---

MIT License.
