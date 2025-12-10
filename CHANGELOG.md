# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2025-12-11

### Fixed
- **harden_sysctl**: Fixed timestamp not expanding in heredoc - now properly records generation time
- **harden_ssh_interactive**: Made SSH config modifications idempotent - no longer accumulates duplicate entries on repeated runs
- **harden_ssh_interactive**: Changed backup strategy from timestamped files to single `.bak` file to prevent accumulation
- **check_updates/setup_unattended_upgrades**: Added error handling for apt commands - script no longer exits on network failures

### Changed
- `set_sshd_option()` now deletes existing config lines before adding new ones (idempotent)
- SSH config backup now uses `sshd_config.bak` instead of `sshd_config.bak.<timestamp>`

---

## [1.1.0] - 2025-12-11

### Added
- **TCP BBR**: Network optimization with `check_bbr_status()`, `enable_bbr()`, `manage_bbr()` functions
- **Kernel Security**: Security parameters audit with `show_sysctl_security()` and hardening with `harden_sysctl()`
- **Quick Port Management**: Easy UFW port management with `quick_allow_port()`, `quick_deny_port()`, `quick_port_management()`
- **Configuration Backup/Restore**: Full backup and restore system with `backup_config()`, `restore_config()`, `list_backups()`
- Common ports selection menu for quick firewall rules (SSH, HTTP, HTTPS, MySQL, PostgreSQL, Redis, MongoDB, etc.)

### Changed
- `menu_init()` now includes BBR and kernel security options (items 8-10)
- `menu_firewall()` now includes quick port management option (item 3)
- `menu_config()` now includes backup/restore options (items 3-5)

### Security
- Kernel security hardening creates `/etc/sysctl.d/99-vps-secure.conf` with recommended parameters
- BBR configuration persisted in `/etc/sysctl.d/99-bbr.conf`
- Backup files stored in `/var/backups/vps-secure-tool/` with restricted permissions (700)

---

## [1.0.0] - 2025-12-11

### Added
- Version control system with `VERSION` file for remote update checking
- Configuration file support (`/etc/vps-secure-tool.conf`)
- Signal handling (SIGINT/SIGTERM) for graceful exit
- SSH public key format validation before writing to authorized_keys
- SSH key type whitelist validation (ed25519, rsa, ecdsa)
- Self-update mechanism with `check_update()` and `do_update()` functions
- Modular menu system with main menu and sub-menus

### Changed
- Refactored code structure into logical modules (CORE, CONFIG, INIT, SECURE, AUDIT, FIREWALL, USER, SSH, LOG, UPDATE, MENU)
- Improved user deletion check to include `$SUDO_USER`
- Improved process check when deleting users
- Replaced deprecated `egrep` with `grep -E`
- Changed fail2ban config to use `backend = systemd` for automatic log detection
- Snapshot generation now falls back to `/tmp` if current directory is not writable

### Fixed
- Fixed `set -e` conflict with `$?` check in `delete_user_safe()` function
- Fixed security risk: replaced `eval echo "~$username"` with `getent passwd`
- Fixed SSH config modification to handle commented lines properly

### Security
- Added input validation for SSH key types
- Added SSH public key format validation
- Removed hardcoded `logpath` in fail2ban config
