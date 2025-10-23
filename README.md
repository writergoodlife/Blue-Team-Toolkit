# CEG Blue Team Automation and Infrastructure Hardening Agent

A comprehensive security automation toolkit designed for rapid vulnerability identification and remediation during the CyberEXPERT Game 2025.

## 🎯 Project Status

**Platform Support:**
- ✅ **Linux** - Fully Implemented (8 scan modules, 3 hardening modules)
- 🔄 **Windows** - Placeholder (To Be Implemented)

**Current Version:** v1.0  
**Last Updated:** October 23, 2025

## ✨ Features

### Security Scanning (8 Modules)

1. **SUID/SGID File Scanner** - Detects suspicious executables with elevated permissions
2. **World-Writable File Scanner** - Finds files/directories with dangerous permissions
3. **Listening Port Scanner** - Identifies potentially unauthorized network services
4. **User Account Scanner** - Detects unauthorized or suspicious user accounts
5. **Weak Password Scanner** - Uses John the Ripper to find easily guessable passwords
6. **SSH Configuration Audit** - Validates SSH security settings
7. **Firewall Rules Verification** - Checks firewall configuration
8. **Docker/Container Security** - Audits container security posture

### Automated Hardening (3 Modules)

1. **SUID/SGID Remediation** - Removes special permissions from suspicious files
2. **Permission Hardening** - Fixes world-writable permissions
3. **User Account Lockdown** - Locks suspicious user accounts

### Real-Time Monitoring 🔥 NEW

- **File Integrity Monitoring** - Detects unauthorized changes to critical files
- **Process Monitoring** - Identifies suspicious processes and backdoors
- **Network Monitoring** - Tracks new listening ports and connections
- **User Activity Tracking** - Monitors logins and account changes
- **SUID Change Detection** - Real-time alerts for new SUID files

### Reporting

- **Comprehensive Reports** - Professional security reports with actionable recommendations
- **Detailed Logging** - Full audit trail of all actions
- **Real-Time Alerts** - Immediate notification of threats (when monitoring)

### 🤖 AI Integration (NEW!)

- **HexStrike MCP Integration** - Use AI agents (Claude, GPT-4, Copilot) to control Blue Team operations
- **Autonomous Security** - AI-powered threat detection and response
- **Competition Automation** - Hands-free competition mode with smart workflows
- **Unified Platform** - Combine Red Team (HexStrike) and Blue Team tools in one interface

## 🚀 Quick Start

```bash
# Navigate to the toolkit
cd /home/goodlife/Desktop/CEG25/blue-team-toolkit

# Run a full security scan
sudo ./linux/blue_agent.sh scan

# Apply automated hardening
sudo ./linux/blue_agent.sh harden

# Generate a comprehensive report
sudo ./linux/blue_agent.sh report

# Start real-time monitoring
sudo ./linux/blue_agent.sh monitor
```

## 📋 Detailed Usage

See [USAGE.md](USAGE.md) for comprehensive documentation.

### Available Commands

```bash
sudo ./linux/blue_agent.sh scan                    # Run all security scans
sudo ./linux/blue_agent.sh harden                  # Apply automated fixes
sudo ./linux/blue_agent.sh monitor                 # Start continuous monitoring
sudo ./linux/blue_agent.sh monitor --duration 300  # Monitor for 5 minutes
sudo ./linux/blue_agent.sh monitor status          # Check monitor status
sudo ./linux/blue_agent.sh monitor stop            # Stop monitoring
sudo ./linux/blue_agent.sh report                  # Generate security report
```

## 📁 Project Structure

```
blue-team-toolkit/
├── config/              # Configuration and baseline files
│   ├── suid_baseline.conf
│   ├── user_baseline.conf
│   └── weak_passwords.txt
├── linux/              # Linux agent
│   └── blue_agent.sh
├── windows/            # Windows agent (placeholder)
│   └── blue_agent.ps1
├── logs/               # Log files and monitoring data
│   ├── blue_agent.log
│   └── monitor/        # Real-time monitoring baselines
│       ├── file_integrity.db
│       ├── process_baseline.txt
│       └── network_baseline.txt
├── tests/              # Testing tools
│   ├── red_team_simulator.sh
│   ├── TEST_PLAN.md
│   └── TEST_RESULTS.md
├── README.md           # This file
├── USAGE.md            # Detailed usage guide
├── MONITOR_GUIDE.md    # Real-time monitoring documentation
├── MCP_INTEGRATION.md  # AI agent integration guide (NEW!)
└── QUICK_REFERENCE.md  # Competition cheat sheet
```

## 🔧 Requirements

### Linux
- Bash 4.0+
- sudo privileges
- John the Ripper (for weak password scanning)
- Optional: Docker (for container security scanning)
- Optional: HexStrike AI MCP Server (for AI agent integration)

### Installation

```bash
# Install required tools
sudo apt update
sudo apt install john

# Make the script executable
chmod +x linux/blue_agent.sh

# Optional: Set up HexStrike MCP integration
# See MCP_INTEGRATION.md for detailed setup
```

## 🎮 Competition Workflow

### Pre-Game Setup
1. Run initial scan to create baselines
2. Review and validate all legitimate files/users
3. Test all modules to ensure proper operation

### During Competition
1. Run full scans every 30-60 minutes
2. Review reports and prioritize critical findings (🚨)
3. Apply hardening actions carefully
4. Monitor logs for suspicious activity

### Post-Game
1. Generate final comprehensive report
2. Review attacker tactics and techniques
3. Document lessons learned

## 📊 Sample Report Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CEG Blue Team Agent Security Report                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Generated on: 2025-10-23 21:36:00
Hostname: parrot
System: Linux 6.12.32-amd64

📋 SSH Configuration Audit Results
────────────────────────────────────────────────────────────────────────────────
⚠️  Status: SSH CONFIGURATION ISSUES DETECTED
⚠️  X11 Forwarding is enabled (potential security risk)

📋 Firewall Configuration Audit Results
────────────────────────────────────────────────────────────────────────────────
🚨 Status: FIREWALL ISSUES DETECTED
🚨 CRITICAL: UFW firewall is INACTIVE

📋 Docker/Container Security Audit Results
────────────────────────────────────────────────────────────────────────────────
🚨 Status: DOCKER SECURITY ISSUES DETECTED
⚠️  Found containers running as root:
  - /onbordo-db
  - /onbordo-frontend
  - /onbordo-backend

💡 Recommendations
────────────────────────────────────────────────────────────────────────────────
• Review and harden SSH configuration (/etc/ssh/sshd_config)
🚨 CRITICAL: Enable and configure UFW firewall immediately!
🚨 CRITICAL: Address Docker security vulnerabilities immediately!
```

## 🔒 Security Notes

### Critical Items to Address Immediately (🚨)
- **Weak passwords** → Force password changes
- **Inactive firewalls** → Enable and configure UFW/iptables
- **Privileged containers** → Remove unnecessary privileges
- **Root SSH login** → Disable in `/etc/ssh/sshd_config`
- **Docker socket exposure** → Fix permissions, remove container mounts

## 🎯 Roadmap

### Completed ✅
- [x] Linux agent core framework
- [x] SUID/SGID file scanner with baseline detection
- [x] World-writable file scanner
- [x] Listening port scanner
- [x] User account scanner
- [x] Weak password scanner (John the Ripper)
- [x] SSH configuration audit
- [x] Firewall rules verification
- [x] Docker/container security checks
- [x] Automated hardening (SUID, permissions, users)
- [x] Comprehensive reporting system
- [x] Detailed logging
- [x] Real-time monitoring (5 detection categories)
- [x] HexStrike MCP Integration (AI-powered operations)

### In Progress 🔄
- [ ] Additional hardening automations (SSH, firewall, Docker auto-config)

### Planned 📅
- [ ] Windows agent implementation
- [ ] Network traffic analysis
- [ ] Incident response playbooks
- [ ] Automated service restoration
- [ ] Web dashboard for monitoring

## 💡 Tips & Best Practices

1. **Always create baselines first** - Run scan before competition to establish normal state
2. **Test hardening carefully** - Verify services work after applying fixes
3. **Prioritize critical findings** - Items marked with 🚨 require immediate attention
4. **Keep reports** - Document all actions for scoring/compliance
5. **Review logs regularly** - Check `logs/blue_agent.log` for detailed activity

## 🤝 Contributing

This is a competition-focused tool. Improvements and additional scan modules are welcome!

## 📝 License

Created for CyberEXPERT Game 2025 preparation.

## 📞 Support

For issues or questions:
- Review logs in `logs/blue_agent.log`
- Check `USAGE.md` for detailed documentation
- Test in a safe environment before competition

---

**⚠️ Important:** This tool is designed to assist, not replace, human decision-making. Always verify findings and test hardening actions before applying in production environments!
