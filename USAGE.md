# Blue Team Toolkit - Usage Guide

## Quick Start

```bash
# Run a full security scan
./linux/blue_agent.sh scan

# Apply automated hardening
./linux/blue_agent.sh harden

# Generate a comprehensive report
./linux/blue_agent.sh report

# Start continuous monitoring
./linux/blue_agent.sh monitor
```

## Scan Modules

### 1. SUID/SGID File Scanner
Detects suspicious executables with elevated permissions using a baseline approach.
- **Baseline File:** `config/suid_baseline.conf`
- **Purpose:** Identify new SUID/SGID files that could be backdoors or privilege escalation tools

### 2. World-Writable File Scanner
Finds files and directories with dangerous world-writable permissions.
- **Risk:** World-writable files can be modified by any user, leading to data corruption or privilege escalation

### 3. Listening Port Scanner
Identifies potentially unauthorized network services.
- **Exclusions:** Configured in `$EXCLUSION_PORTS` array
- **Purpose:** Detect rogue services or backdoors listening on the network

### 4. User Account Scanner
Detects unauthorized or suspicious user accounts.
- **Baseline File:** `config/user_baseline.conf`
- **Purpose:** Identify newly created accounts that could be backdoor access

### 5. Weak Password Scanner
Uses John the Ripper to check for easily guessable passwords.
- **Wordlist:** `config/weak_passwords.txt`
- **Purpose:** Identify accounts vulnerable to password-based attacks

### 6. SSH Configuration Audit ✨NEW
Checks SSH daemon configuration for security issues.
- **Checks:**
  - Root login permissions
  - Password authentication settings
  - Empty password allowance
  - SSH protocol version
  - X11 forwarding
  - MaxAuthTries setting

### 7. Firewall Rules Verification ✨NEW
Validates firewall configuration and rules.
- **Supports:** UFW and iptables
- **Checks:**
  - Firewall active/inactive status
  - Overly permissive rules
  - Default policies

### 8. Docker/Container Security ✨NEW
Audits Docker containers for security vulnerabilities.
- **Checks:**
  - Privileged containers
  - Containers running as root
  - Host network mode usage
  - Docker socket permissions
  - Docker socket mounts

## Hardening Actions

The `harden` module automatically remediates the following:

1. **SUID/SGID Files:** Removes special permissions from suspicious executables
2. **World-Writable Files:** Removes world-writable permissions
3. **Suspicious Users:** Locks accounts not in baseline

## Configuration

### Baseline Files
- `config/suid_baseline.conf` - Known legitimate SUID/SGID files
- `config/user_baseline.conf` - Known legitimate user accounts
- `config/weak_passwords.txt` - Common weak passwords to check

### Exclusions
Edit the script to modify:
- `EXCLUSION_IPS` - IP addresses to ignore in port scans
- `EXCLUSION_PORTS` - Ports to ignore in port scans

## Reports

Reports are saved to: `/home/goodlife/Desktop/CEG25/reports/`

Each report includes:
- Detailed findings for all scan modules
- Summary statistics
- Actionable recommendations
- Links to full logs

## Logs

All activity is logged to: `logs/blue_agent.log`

## Best Practices

1. **Run scans regularly** - Ideally every hour during competition
2. **Review reports** - Don't just automate, understand the findings
3. **Test hardening** - Verify services still work after applying fixes
4. **Update baselines** - Add legitimate files/users to baselines as needed
5. **Monitor continuously** - Use the monitor module for real-time detection

## Troubleshooting

### "Permission denied" errors
Most scans require sudo privileges. Run with appropriate permissions.

### Baseline not found
The script will auto-create baselines on first run from current system state.

### John the Ripper not found
Install: `sudo apt install john`

### Docker scan skipped
Docker daemon must be running: `sudo systemctl start docker`

## Security Notes

⚠️ **CRITICAL ITEMS TO ADDRESS IMMEDIATELY:**
- Weak passwords (force password changes)
- Inactive firewalls (enable and configure)
- Privileged Docker containers (remove privileges)
- Root SSH login (disable in `/etc/ssh/sshd_config`)
- Docker socket exposures (remove mounts, fix permissions)

## Competition Tips

1. **Pre-game Setup:**
   - Create all baselines before competition starts
   - Test all modules to ensure they work
   - Document known legitimate services/users
   
2. **During Competition:**
   - Run full scans every 30-60 minutes
   - Prioritize critical findings (marked with 🚨)
   - Apply hardening carefully (test services afterward)
   - Keep reports for scoring/documentation
   
3. **Post-game:**
   - Review logs for attacker TTPs
   - Document lessons learned
   - Update tool for next competition
