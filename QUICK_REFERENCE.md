# Blue Team Agent - Quick Reference Card

## 🚀 Essential Commands

### Run Full Scan
```bash
sudo ./linux/blue_agent.sh scan
```
**Time:** 2-7 minutes  
**Output:** Logs to `blue_agent.log`

### Generate Report
```bash
sudo ./linux/blue_agent.sh report
```
**Output:** Creates timestamped report in `reports/`

### Auto-Harden System
```bash
sudo ./linux/blue_agent.sh harden
```
**Fixes:** SUID bits, file permissions, locks suspicious users

### Full Workflow
```bash
sudo ./linux/blue_agent.sh scan && \
sudo ./linux/blue_agent.sh report && \
sudo ./linux/blue_agent.sh harden
```

---

## 📊 What Gets Scanned

| Module | Detection | Time |
|--------|-----------|------|
| **SUID/SGID** | Unauthorized privileged binaries | 10-20s |
| **World-Writable** | 777 files/directories | 15-30s |
| **Listening Ports** | Unauthorized network services | <1s |
| **User Accounts** | Backdoor/suspicious users | <1s |
| **Weak Passwords** | John the Ripper cracking | 1-5min |
| **SSH Config** | Insecure SSH settings | <1s |
| **Firewall** | UFW/iptables status & rules | <1s |
| **Docker** | Privileged containers & misconfigs | 1-3s |

---

## 🎯 Priority Response Order

### 1. CRITICAL (Immediate Action) 🚨
- **Weak Passwords** → Force password changes
- **Firewall Inactive** → Enable UFW immediately
- **Privileged Containers** → Stop/inspect containers

### 2. HIGH (Within 5 min) ⚠️
- **New SUID files** → Remove SUID bit or delete
- **Backdoor users** → Lock accounts
- **SSH misconfigurations** → Edit `/etc/ssh/sshd_config`

### 3. MEDIUM (Within 15 min) 📋
- **World-writable files** → Fix permissions
- **Suspicious ports** → Kill processes or whitelist

---

## 🔍 Manual Investigation Commands

### Check Specific Findings
```bash
# View latest scan log
tail -100 blue_agent.log

# Search for critical issues
grep "🚨" blue_agent.log

# List all findings
ls -lh logs/findings_*.txt
```

### Process Investigation
```bash
# Find process on suspicious port
sudo ss -tulpn | grep :4444

# Kill suspicious process
sudo kill -9 <PID>

# Check all listening services
sudo netstat -tulpn
```

### User Investigation
```bash
# Check user status
sudo passwd -S <username>

# View user login history
last <username>

# Lock suspicious user
sudo usermod -L <username>
```

### File Investigation
```bash
# Check SUID files in real-time
find / -perm -4000 -type f 2>/dev/null

# Check who modified a file
stat /path/to/file

# Remove SUID bit
sudo chmod u-s /path/to/file
```

---

## ⚡ Competition Quick Actions

### T+0: Start (Pre-Baseline)
```bash
cd /path/to/blue-team-toolkit
sudo ./linux/blue_agent.sh scan  # Creates baseline
```

### T+10: First Detection
```bash
sudo ./linux/blue_agent.sh scan
grep "SUSPICIOUS\|🚨" blue_agent.log
```

### T+15: Auto-Remediate
```bash
sudo ./linux/blue_agent.sh harden
```

### T+20: Verify & Re-scan
```bash
sudo ./linux/blue_agent.sh scan
sudo ./linux/blue_agent.sh report | less
```

### T+25: Manual Cleanup (if needed)
```bash
# Kill backdoor listeners
sudo pkill -f "nc -l"

# Enable firewall
sudo ufw enable
sudo ufw default deny incoming

# Harden SSH
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

---

## 🛡️ Emergency Manual Commands

### If Tool Fails - Manual Detection
```bash
# Find SUID files
find / -perm -4000 -type f 2>/dev/null > /tmp/suid_check.txt

# Find world-writable
find / -type f -perm -002 2>/dev/null

# Check users
cut -d: -f1 /etc/passwd | sort

# Check ports
sudo ss -tulpn
```

### Quick Hardening
```bash
# Lock all non-system users
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    sudo usermod -L $user
done

# Disable root SSH
echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart ssh

# Enable firewall with restrictive rules
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
```

---

## 📝 Configuration Files

| File | Purpose |
|------|---------|
| `config/suid_baseline.conf` | Known legitimate SUID files |
| `config/user_baseline.conf` | Known legitimate users |
| `config/weak_passwords.txt` | Password wordlist for John |
| `logs/blue_agent.log` | All scan results & actions |
| `reports/report_*.txt` | Formatted security reports |

### Update Baseline
```bash
# If legitimate changes made, update baseline:
sudo rm config/suid_baseline.conf
sudo ./linux/blue_agent.sh scan  # Creates new baseline
```

---

## ⚙️ Common Issues & Fixes

### Issue: "Permission denied"
**Fix:** Always run with `sudo`

### Issue: John the Ripper hangs
**Fix:** `Ctrl+C` to skip, or reduce wordlist size

### Issue: Too many false positives
**Fix:** Review and whitelist in baseline files

### Issue: Tool not detecting
**Fix:** Ensure baselines exist and are current

---

## 🔥 Speed Optimizations

### Skip Slow Scans (Competition Mode)
```bash
# Edit blue_agent.sh, comment out:
# scan_weak_passwords  # Takes 1-5 minutes
```

### Parallel Scanning (if multiple systems)
```bash
# Terminal 1
sudo ./linux/blue_agent.sh scan &

# Terminal 2
ssh other-server 'sudo /path/to/blue_agent.sh scan' &
```

---

## 💡 Pro Tips

1. **Pre-create baselines** before competition starts
2. **Monitor logs in real-time**: `tail -f blue_agent.log`
3. **Prioritize critical findings** (🚨) first
4. **Re-scan after hardening** to verify fixes
5. **Keep USB backup** of toolkit in case of system issues
6. **Practice workflow** at least 3 times before competition
7. **Know manual commands** as fallback if script fails
8. **Check baseline accuracy** - don't whitelist red team implants!

---

## 📞 Scoring Checklist

- [ ] Firewall enabled and configured
- [ ] No weak passwords detected
- [ ] All unauthorized SUID files removed
- [ ] No backdoor user accounts
- [ ] SSH hardened (no root login, key-based auth)
- [ ] No suspicious listening ports
- [ ] World-writable files corrected
- [ ] Docker containers secured
- [ ] All services properly configured
- [ ] System logs reviewed for anomalies

---

## 🎓 Remember

**"Detect Fast, Harden Faster, Verify Always"**

1. **Scan** → Find threats
2. **Report** → Understand scope
3. **Harden** → Auto-remediate
4. **Verify** → Re-scan to confirm
5. **Manual** → Handle remaining issues

**Good luck! 🛡️🏆**
