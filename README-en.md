# vps-secure-tool · VPS Ops & Security Toolbox

[中文版 / Chinese Version](./README-zh.md)

An **ops and security toolbox for VPS (Virtual Private Server)**, designed for individual developers.

The script provides an interactive menu to help you perform common security hardening and operations tasks, without memorizing long command lines.

---

## 🧩 Feature Overview

> For the first occurrence, abbreviations are expanded with their full names.

### System Initialization & Optimization
- Swap memory management (auto-calculate recommended size, create/remove)
- Time synchronization (chrony) and timezone configuration
- TCP BBR congestion control optimization (significantly improves network performance)
- Kernel security parameter hardening (sysctl auto-configuration)

### User & SSH (Secure Shell) Security
- Create secure SSH users (key-only login, or password + key)
- Automatically creates `~/.ssh/authorized_keys` with correct permissions
- Disable remote root login and password authentication (public key only)
- Change SSH port (automatically syncs UFW rules)

### Firewall & Protection
- Inspect and configure UFW (Uncomplicated Firewall) rules
- **Quick port management** (HTTP/HTTPS/MySQL/PostgreSQL/Redis/MongoDB and 9 common ports)
- Install and configure fail2ban (brute-force protection), banning suspicious IPs

### Monitoring & Auditing
- View system info, resource usage (CPU/memory/disk/load)
- Inspect SSH configuration, firewall status, auth logs
- SUID (Set-User-ID) binary inspection, cron job overview
- **Generate security audit reports** (with [PASS]/[WARN]/[FAIL] markers)
- One-shot security snapshot log generation

### Configuration Management
- Configuration file support (`/etc/vps-secure-tool.conf`)
- **Configuration backup & restore** (SSH/UFW/fail2ban/sysctl one-click package)
- Automatic script update detection and upgrade

Goal: **After you log into a VPS, just run this script first and drive everything from the menu.**

---

## ⚡ One-Line Install & Run (Quick Start)

> ⚠️ Note: This is the classic `curl | bash` pattern, convenient but implicit.  
> For security, you should **read the script source at least once** (see next section).


```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/IsaacZhaoo/vps-secure-tool/main/vps_secure_tool.sh)"
```

---

## ✅ Safer Installation Flow (Recommended)

For first-time usage, it is safer to follow a “download → inspect → run” workflow:

```bash
# 1. Download the script
curl -fsSL https://raw.githubusercontent.com/IsaacZhaoo/vps-secure-tool/main/vps_secure_tool.sh -o vps_secure_tool.sh

# 2. Inspect the script (pick one)
less vps_secure_tool.sh
# or
nano vps_secure_tool.sh

# 3. Make it executable
chmod +x vps_secure_tool.sh

# 4. Run as root / via sudo
sudo ./vps_secure_tool.sh
```

> 🔒 Tip:  
> Keep your current SSH session open while changing security-related configs.  
> Only log out after you have successfully tested the new login path (for example, new user + key-based login) from another session.

---

## 🖥️ Supported Environment

- Operating system:  
  - Recommended: Debian / Ubuntu family distributions  
  - On other Linux distros, some features (such as `apt` / `ufw` / `unattended-upgrades`) may not work
- Privileges:  
  - Must be run as `root` or a user with `sudo` privileges
- Dependencies:  
  - Required: `bash`, `sshd` (OpenSSH server), common system tool (`ip`, `ss` or `netstat`, `free`, `df`, `ps`, etc.)  
  - Optional: `ufw`, `fail2ban` (can be installed automatically on Debian / Ubuntu)

---

## 📋 Menu Items in Detail

Once launched, the script shows a bilingual menu; choose actions by number.

### Main Menu Structure

The script uses a categorized sub-menu design with 7 main categories:

1. **System Initialization** - System info, resource monitoring, updates, Swap, time sync, BBR, kernel hardening
2. **User & SSH Management** - Create users, SSH config, port changes, security hardening
3. **Firewall Management** - UFW configuration, fail2ban, quick port management
4. **Logs & Monitoring** - Listening ports, auth logs, cron jobs, system monitoring tools
5. **Security Audit** - SUID check, security snapshot, audit report generation
6. **Configuration Management** - View/edit config, backup/restore
7. **Updates & About** - Check updates, perform updates, version info

### Key Features

**System Initialization**
- Swap Management: Auto-calculates recommended size (≤2GB RAM uses 2GB, >2GB uses equal amount, max 4GB)
- TCP BBR: One-click enable BBR congestion control algorithm for better network performance
- Kernel Security: Disables IP forwarding, ICMP redirects, enables ASLR and 10+ hardening parameters

**Firewall Management**
- Quick Port Management: Support for 9 common ports with one-click allow/deny
  - SSH(22), HTTP(80), HTTPS(443), MySQL(3306), PostgreSQL(5432)
  - Redis(6379), MongoDB(27017), Alt-HTTP(8080), Alt-HTTPS(8443)

**Security Audit**
- Audit Report: Auto-checks SSH, firewall, user permissions, generates [PASS]/[WARN]/[FAIL] marked report

**Configuration Management**
- Backup: Packages SSH/UFW/fail2ban/sysctl configs to `/var/backups/vps-secure-tool/`
- Restore: Restores configs from backup file, optional service restart  

---

## 🔄 Suggested Usage Flow (Example)

A typical flow for a freshly provisioned VPS:

1. Generate an SSH key pair on your local machine and ensure you can log into the VPS as a non-root user using the key.  
2. Run this script on the VPS:  
   - Log in as `root` or a temporary user with `sudo`.  
   - Use the menu:  
     - `6`: Create a secure ops user with key-only login and add it to the sudo group.  
     - (Optional) `10`: Change the SSH port from 22 to a non-standard port.  
     - `9`: Disable root SSH login and password authentication (public key only).  
     - `12`: Enable UFW and only allow SSH / 80 / 443.  
     - `14`: Install and enable fail2ban.  
   - Open a new terminal and test logging in with the new user + key. Confirm it works before closing the original session.  
3. Use:  
   - `15` / `16` / `18` for regular security checks;  
   - `19` to generate snapshot logs for your personal “server learning records”.  

---

## ⚠️ Disclaimer

- This script *does* modify security-critical configuration (SSH, UFW, firewall rules, fail2ban, etc.). Before using it:  
  - Make sure you have at least one working SSH key-based login path;  
  - Do not close your current SSH session while applying changes;  
  - Verify that the new configuration (e.g., new user, new port) works from a separate session before logging out.  
- The author is not responsible for any direct or indirect damage caused by using this script. Use it at your own risk.  

---

## 📜 License

This project is licensed under the **MIT License**.

You are free to copy, modify, and distribute this script, as long as you retain the license notice.
