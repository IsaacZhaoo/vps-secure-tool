# vps-secure-tool · VPS Ops & Security Toolbox

[中文版 / Chinese Version](./README-zh.md)

An **ops and security toolbox for VPS (Virtual Private Server)**, designed for individual developers.

The script provides an interactive menu to help you perform common security hardening and operations tasks, without memorizing long command lines.

---

## 🧩 Feature Overview

> For the first occurrence, abbreviations are expanded with their full names.

Main capabilities:

- Create secure SSH (Secure Shell) users  
  - Key-only login, or password + key  
  - Automatically creates `~/.ssh/authorized_keys` with correct permissions
- Disable remote root login and password authentication (public key only)
- Inspect and configure UFW (Uncomplicated Firewall) rules
- Install and configure fail2ban (brute-force protection), banning suspicious IPs
- Inspect SSH configuration, firewall status, auth logs, SUID (Set-User-ID) binaries, and cron jobs
- Generate one-shot security snapshot logs for auditing and learning notes

Goal: **After you log into a VPS, just run this script first and drive everything from the menu.**

---

## ⚡ One-Line Install & Run (Quick Start)

> ⚠️ Note: This is the classic `curl | bash` pattern, convenient but implicit.  
> For security, you should **read the script source at least once** (see next section).


```bash
curl -fsSL https://raw.githubusercontent.com/IsaacZhaoo/vps-secure-tool/main/vps_secure_tool.sh | sudo bash
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

### Menu (Short Description)

1. Switch UI language (Chinese / English)  
2. Show basic system info (hostname, OS release, kernel, network interfaces & IPs)  
3. Show system resource usage (memory / disk / top memory-hungry processes)  
4. Check available updates via `apt` and optionally run `apt upgrade`  
5. Configure automatic security updates via `unattended-upgrades`  
6. Create a secure SSH user  
   - Key-only login (recommended) or password + key  
   - Automatically creates `.ssh` and `authorized_keys` with safe permissions  
   - Optionally add user to `sudo` / `wheel` group  
   - Supports pasting an existing public key or generating a key pair on the server (with a security warning)  
7. Inspect users and sudo privileges (`sudo` / `wheel` groups, `/etc/sudoers.d`)  
8. Inspect SSH configuration (including key fields from `sshd -T`)  
9. SSH basic hardening:  
   - `PermitRootLogin no` (disallow root SSH login)  
   - `PasswordAuthentication no` (disable password login, public key only)  
   - Automatically back up config, run syntax check, and restart `ssh` / `sshd`  
10. Change SSH port (and open the new port in UFW automatically)  
11. Check firewall status (UFW / firewalld)  
12. Setup basic UFW rules: allow OpenSSH / 80 / 443, deny other incoming traffic by default  
13. Check fail2ban status (including `sshd` jail)  
14. Install and configure fail2ban for sshd protection  
15. Show current listening ports and owning processes (`ss -tulpen` / `netstat -tulpen`)  
16. Show SSH auth log summary (`/var/log/auth.log` + records containing “Failed password”)  
17. Show cron jobs overview: root crontab / `/etc/crontab` / `/etc/cron*`  
18. Quick check of SUID binaries (first 50) for security review  
19. Generate a one-shot security snapshot log (saved to current directory)  
20. Lock the root account password (does not affect `sudo`, only direct root password login)  
0. Exit the script  

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
