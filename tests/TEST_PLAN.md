# Blue Team Agent - Test Plan

## Overview
This test plan validates all scanning and hardening capabilities of the Blue Team Agent before competition deployment.

## Test Environment Setup

### Prerequisites
- Clean Linux system (or VM snapshot)
- Sudo access
- John the Ripper installed
- Docker installed (optional, for Docker tests)
- Netcat (nc) installed

### Baseline Creation
1. Clean the system of any test artifacts
2. Run blue_agent.sh to create fresh baselines
3. Verify baseline files are created in `config/`

## Test Matrix

### Test 1: SUID/SGID Detection
**Objective:** Verify detection of unauthorized SUID/SGID files

**Steps:**
```bash
# 1. Create baseline
sudo ./linux/blue_agent.sh scan

# 2. Simulate red team action
sudo ./tests/red_team_simulator.sh suid

# 3. Run scan
sudo ./linux/blue_agent.sh scan

# 4. Verify detection
grep -A 5 "SUID/SGID Files" blue_agent.log
```

**Expected Results:**
- ✅ `/tmp/red_team_backdoor` should be detected
- ✅ Finding should appear in report
- ✅ Log should show "Not in baseline"

**Hardening Test:**
```bash
sudo ./linux/blue_agent.sh harden
ls -l /tmp/red_team_backdoor  # Should show no SUID bit
```

---

### Test 2: World-Writable Files Detection
**Objective:** Verify detection of world-writable files/directories

**Steps:**
```bash
# 1. Simulate red team action
sudo ./tests/red_team_simulator.sh writable

# 2. Run scan
sudo ./linux/blue_agent.sh scan

# 3. Verify detection
grep -A 5 "World-Writable" blue_agent.log
```

**Expected Results:**
- ✅ `/tmp/exfil_data.txt` should be detected
- ✅ `/tmp/red_team_staging/` should be detected
- ✅ Permissions should be shown (777)

**Hardening Test:**
```bash
sudo ./linux/blue_agent.sh harden
ls -ld /tmp/exfil_data.txt  # Should show 644
ls -ld /tmp/red_team_staging  # Should show 755
```

---

### Test 3: User Account Detection
**Objective:** Verify detection of unauthorized user accounts

**Steps:**
```bash
# 1. Simulate red team action
sudo ./tests/red_team_simulator.sh user

# 2. Run scan
sudo ./linux/blue_agent.sh scan

# 3. Verify detection
grep -A 5 "Excessive Users" blue_agent.log
```

**Expected Results:**
- ✅ `red_admin` should be detected
- ✅ Should show "Not in baseline"
- ✅ Report should list UID and shell

**Hardening Test:**
```bash
sudo ./linux/blue_agent.sh harden
sudo passwd -S red_admin  # Should show locked (L)
```

---

### Test 4: Weak Password Detection
**Objective:** Verify John the Ripper integration and weak password detection

**Steps:**
```bash
# 1. Simulate red team action
sudo ./tests/red_team_simulator.sh weakpass

# 2. Run scan (this takes time)
sudo ./linux/blue_agent.sh scan

# 3. Check results
grep -A 10 "Weak Passwords" blue_agent.log
```

**Expected Results:**
- ✅ `compromised_user` should be detected
- ✅ Password "password" should be cracked
- ✅ Alert should show in report with 🚨

**Note:** This test can take 1-5 minutes depending on system performance.

---

### Test 5: Listening Ports Detection
**Objective:** Verify detection of listening network ports

**Steps:**
```bash
# 1. Simulate red team action
sudo ./tests/red_team_simulator.sh port

# 2. Run scan
sudo ./linux/blue_agent.sh scan

# 3. Verify detection
grep -A 20 "Listening Ports" blue_agent.log
```

**Expected Results:**
- ✅ Port 4444 should be detected
- ✅ Should show TCP protocol
- ✅ Process name (nc) should be shown

**Cleanup:**
```bash
# Kill the backdoor listener
sudo ./tests/red_team_simulator.sh clean
```

---

### Test 6: SSH Configuration Audit
**Objective:** Verify SSH security configuration checks

**Steps:**
```bash
# 1. Check current SSH config
sudo cat /etc/ssh/sshd_config | grep -E "PermitRootLogin|PasswordAuthentication"

# 2. Run scan
sudo ./linux/blue_agent.sh scan

# 3. Verify audit
grep -A 10 "SSH Configuration" blue_agent.log
```

**Expected Results:**
- ✅ All 6 SSH checks should be performed
- ✅ PermitRootLogin status shown
- ✅ PasswordAuthentication status shown
- ✅ Protocol version verified
- ✅ Recommendations for insecure settings

**Common Findings:**
- ⚠️ PermitRootLogin yes (should be no)
- ⚠️ PasswordAuthentication yes (consider key-based)
- ⚠️ X11Forwarding yes (disable if unused)

---

### Test 7: Firewall Rules Verification
**Objective:** Verify firewall configuration audit

**Steps:**
```bash
# 1. Check firewall status
sudo ufw status || sudo iptables -L

# 2. Run scan
sudo ./linux/blue_agent.sh scan

# 3. Verify audit
grep -A 10 "Firewall Rules" blue_agent.log
```

**Expected Results:**
- ✅ Firewall status detected (active/inactive)
- ✅ Permissive rules identified
- ✅ Recommendations provided if inactive
- ✅ Both UFW and iptables checked

**Critical Finding:**
- 🚨 UFW inactive = immediate critical alert

---

### Test 8: Docker Security Checks
**Objective:** Verify Docker container security audit

**Prerequisites:** Docker must be installed and running

**Steps:**
```bash
# 1. Simulate red team action
sudo ./tests/red_team_simulator.sh docker

# 2. Run scan
sudo ./linux/blue_agent.sh scan

# 3. Verify detection
grep -A 15 "Docker/Container Security" blue_agent.log
```

**Expected Results:**
- ✅ Privileged container detected
- ✅ Container details shown (name, image)
- ✅ Security issues listed
- ✅ Recommendations provided

**Cleanup:**
```bash
sudo docker stop red_team_container
sudo docker rm red_team_container
```

---

## Full Integration Test

### Scenario: Complete Red Team Simulation

**Objective:** Run all red team actions and verify blue agent detects everything

**Steps:**
```bash
# 1. Clean environment
sudo ./tests/red_team_simulator.sh clean
sudo rm -f blue_agent.log findings_*.txt

# 2. Create fresh baseline
sudo ./linux/blue_agent.sh scan

# 3. Deploy full red team attack
sudo ./tests/red_team_simulator.sh all

# 4. Run blue agent detection
sudo ./linux/blue_agent.sh scan

# 5. Generate report
sudo ./linux/blue_agent.sh report

# 6. Run automated hardening
sudo ./linux/blue_agent.sh harden

# 7. Re-scan to verify remediation
sudo ./linux/blue_agent.sh scan

# 8. Final report
sudo ./linux/blue_agent.sh report
```

**Expected Results:**
- ✅ All 8 threats detected in initial scan
- ✅ Report shows all findings with severity
- ✅ Hardening remediates SUID, permissions, users
- ✅ Re-scan shows reduced findings
- ✅ Final report shows improvement

**Success Criteria:**
- 8/8 detections in initial scan
- 3+ remediations successful
- No false positives from baseline
- Report is clear and actionable

---

## Performance Testing

### Scan Time Benchmarks

**Test System:** Parrot OS Linux (adjust for your system)

| Module | Expected Time |
|--------|---------------|
| SUID/SGID Scan | 5-15 seconds |
| World-Writable Scan | 10-30 seconds |
| Listening Ports | <1 second |
| User Account Scan | <1 second |
| Weak Password Scan | 1-5 minutes |
| SSH Config Audit | <1 second |
| Firewall Verification | <1 second |
| Docker Security | 1-3 seconds |
| **Total** | **2-7 minutes** |

**Note:** Weak password scan dominates runtime. Consider limiting in competitions with time constraints.

---

## Edge Cases & Stress Testing

### Edge Case 1: No John the Ripper
```bash
sudo mv /usr/bin/john /usr/bin/john.backup
sudo ./linux/blue_agent.sh scan
# Should skip weak password scan gracefully
```

### Edge Case 2: No Docker Installed
```bash
# Should skip Docker checks without error
```

### Edge Case 3: Empty Baseline
```bash
rm config/suid_baseline.conf
sudo ./linux/blue_agent.sh scan
# Should create new baseline
```

### Edge Case 4: Large Number of SUID Files
```bash
# Create 100 SUID files
for i in {1..100}; do
    sudo touch /tmp/suid_test_$i
    sudo chmod u+s /tmp/suid_test_$i
done
sudo ./linux/blue_agent.sh scan
# Should detect all without crash
```

---

## Competition Simulation

### Realistic Competition Workflow

**Timeline:** 30-minute competition window

```bash
# T+0: Competition starts
cd /path/to/blue-team-toolkit

# T+1: Initial baseline (if not pre-created)
sudo ./linux/blue_agent.sh scan

# T+5: Red team starts attacking
# (They plant backdoors, create users, etc.)

# T+10: Run detection scan
sudo ./linux/blue_agent.sh scan

# T+12: Review report
sudo ./linux/blue_agent.sh report | less

# T+15: Run automated hardening
sudo ./linux/blue_agent.sh harden

# T+17: Verify remediation
sudo ./linux/blue_agent.sh scan

# T+20: Manual investigation of critical findings
grep "🚨" blue_agent.log

# T+25: Final defensive posture check
sudo ./linux/blue_agent.sh report

# T+30: Competition ends
```

**Key Metrics:**
- Time to first detection: <10 minutes
- Time to remediation: <20 minutes
- False positive rate: <5%
- Detection accuracy: >90%

---

## Test Results Log

### Test Run: [Date]

**System:** [OS Version]  
**Tester:** [Name]  
**Duration:** [Minutes]

| Test | Status | Notes |
|------|--------|-------|
| SUID Detection | ⬜ Pass / ⬜ Fail | |
| Writable Files | ⬜ Pass / ⬜ Fail | |
| User Accounts | ⬜ Pass / ⬜ Fail | |
| Weak Passwords | ⬜ Pass / ⬜ Fail | |
| Listening Ports | ⬜ Pass / ⬜ Fail | |
| SSH Audit | ⬜ Pass / ⬜ Fail | |
| Firewall Check | ⬜ Pass / ⬜ Fail | |
| Docker Security | ⬜ Pass / ⬜ Fail | |
| Integration Test | ⬜ Pass / ⬜ Fail | |
| Performance | ⬜ Pass / ⬜ Fail | |

**Overall Assessment:** ⬜ Ready for Competition / ⬜ Needs Work

**Issues Found:**
- 

**Recommendations:**
- 

---

## Next Steps After Testing

1. ✅ **Document Edge Cases** - Add any discovered issues to README
2. ✅ **Optimize Performance** - If scans take too long, optimize find commands
3. ✅ **Create Quick Reference Card** - One-page cheat sheet for competition
4. ⬜ **Practice Run** - Do 2-3 full competition simulations
5. ⬜ **Team Training** - If working with teammates, train them on the tool
6. ⬜ **Backup Plan** - Have manual commands ready if tool fails

---

## Troubleshooting Guide

### Issue: "Permission denied" errors
**Solution:** Run with sudo: `sudo ./linux/blue_agent.sh scan`

### Issue: John the Ripper hangs
**Solution:** Ctrl+C and check `/var/log/john.log`, may need to reduce wordlist

### Issue: Baseline contains red team artifacts
**Solution:** Clean system first with `red_team_simulator.sh clean`, then re-run

### Issue: Too many false positives
**Solution:** Review and update baseline files in `config/` directory

### Issue: Report not showing findings
**Solution:** Check `findings_*.txt` files exist and contain data

---

## Competition Day Checklist

- [ ] Clean system and create fresh baselines
- [ ] Verify all dependencies installed (john, nc, docker)
- [ ] Test run blue_agent.sh to ensure no errors
- [ ] Copy toolkit to USB drive (backup)
- [ ] Print quick reference card
- [ ] Set up terminal window with command history
- [ ] Configure log monitoring: `tail -f blue_agent.log`
- [ ] Pre-stage sudo access (don't time out)
- [ ] Know manual commands as fallback
- [ ] Have Discord/Slack ready for team coordination

**Good luck! 🛡️**
