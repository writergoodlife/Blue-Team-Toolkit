# Monitor Module - Real-Time Security Monitoring

## Overview

The Monitor Module provides continuous real-time security monitoring for your system. It watches for suspicious activity and sends immediate alerts when threats are detected.

---

## Features

### 🔍 What It Monitors:

1. **File Integrity**
   - Monitors critical system files for unauthorized changes
   - Tracks: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, etc.
   - Uses SHA256 checksums for verification

2. **Process Activity**
   - Detects suspicious process patterns
   - Flags processes running from `/tmp` or `/dev/shm`
   - Identifies reverse shells, backdoors, and web servers

3. **Network Connections**
   - Monitors for new listening ports
   - Detects suspicious outbound connections
   - Tracks connections to common C2 ports (4444, 5555, 31337, etc.)

4. **User Activity**
   - Tracks remote logins
   - Monitors failed login attempts
   - Detects new user account creation

5. **SUID/SGID Changes**
   - Scans for new SUID/SGID files in suspicious locations
   - Monitors `/tmp`, `/var/tmp`, `/dev/shm`, `/home`

---

## Usage

### Start Monitoring

**Indefinite monitoring** (runs until manually stopped):
```bash
sudo ./linux/blue_agent.sh monitor
```

**Timed monitoring** (auto-stops after duration):
```bash
sudo ./linux/blue_agent.sh monitor --duration 300
# Runs for 300 seconds (5 minutes)
```

### Check Status

```bash
sudo ./linux/blue_agent.sh monitor status
```

**Output:**
```
Status: RUNNING
PID: 12345
Runtime: 00:05:32
Logs: ./logs/blue_agent.log

Recent Alerts (last 10):
────────────────────────────────────────────────────────
[2025-10-23 22:01:39] 🚨 [MONITOR] ALERT: SUID/SGID file detected: /tmp/backdoor
```

### Stop Monitoring

```bash
sudo ./linux/blue_agent.sh monitor stop
```

### View Live Logs

```bash
tail -f logs/blue_agent.log | grep MONITOR
```

Or for alerts only:
```bash
tail -f logs/blue_agent.log | grep -E "ALERT|🚨|⚠️"
```

---

## How It Works

### 1. Baseline Creation

On first run, the monitor creates three baselines:

- **File Integrity Database** (`logs/monitor/file_integrity.db`)
  - SHA256 checksums of critical system files
  
- **Process Baseline** (`logs/monitor/process_baseline.txt`)
  - Snapshot of current running processes
  
- **Network Baseline** (`logs/monitor/network_baseline.txt`)
  - Current listening ports and connections

### 2. Continuous Monitoring Loop

Every 10 seconds, the monitor:
1. Checks file integrity against baseline
2. Scans for suspicious processes
3. Monitors network connections
4. Checks user activity
5. Scans for SUID/SGID changes

### 3. Alert Levels

| Symbol | Level | Description |
|--------|-------|-------------|
| 🚨 | **ALERT** | Critical security event - immediate action required |
| ⚠️ | **WARNING** | Suspicious activity detected - investigation needed |
| ℹ️ | **INFO** | Normal activity logged for awareness |

---

## Detection Examples

### Example 1: File Integrity Violation

**Scenario:** Attacker modifies `/etc/passwd`

**Detection:**
```
🚨 [MONITOR] ALERT: File integrity violation detected: /etc/passwd
[MONITOR] Expected: a1b2c3d4..., Got: e5f6g7h8...
```

### Example 2: Backdoor Process

**Scenario:** Attacker starts netcat listener

**Detection:**
```
🚨 [MONITOR] ALERT: Suspicious process detected: nc -l
[MONITOR] Details: user pts/0 12345 0.0 0.1 nc -lvnp 4444
```

### Example 3: New Listening Port

**Scenario:** Service opens unauthorized port

**Detection:**
```
⚠️ [MONITOR] ALERT: New listening port detected: 8888
[MONITOR] Details: tcp LISTEN 0.0.0.0:8888 users:(("python3",pid=12345))
```

### Example 4: New User Account

**Scenario:** Attacker creates backdoor user

**Detection:**
```
🚨 [MONITOR] ALERT: New user account(s) created:
[MONITOR] - backdoor_admin
```

### Example 5: SUID File in /tmp

**Scenario:** Privilege escalation attempt

**Detection:**
```
🚨 [MONITOR] ALERT: SUID/SGID file detected in suspicious location: /tmp/exploit
```

---

## Configuration

### Adjust Check Interval

Edit `blue_agent.sh` and modify:
```bash
MONITOR_INTERVAL=10  # seconds between checks
```

**Recommendations:**
- **Competition:** 10-15 seconds (balance speed vs. performance)
- **Production:** 30-60 seconds (reduce system load)
- **High-Security:** 5 seconds (maximum responsiveness)

### Add Custom File Integrity Checks

Edit the `create_file_integrity_baseline()` function:
```bash
CRITICAL_PATHS=(
    "/etc/passwd"
    "/etc/shadow"
    "/your/custom/file"  # Add your files here
)
```

### Customize Suspicious Process Patterns

Edit the `check_suspicious_processes()` function:
```bash
SUSPICIOUS_PATTERNS=(
    "nc -l"
    "ncat -l"
    "your_pattern"  # Add custom patterns
)
```

---

## Integration with Other Modules

### Workflow 1: Monitor + Scan + Harden

```bash
# Terminal 1: Start monitoring
sudo ./linux/blue_agent.sh monitor &

# Terminal 2: Run periodic scans
while true; do
    sudo ./linux/blue_agent.sh scan
    sudo ./linux/blue_agent.sh harden
    sleep 300  # Every 5 minutes
done
```

### Workflow 2: Competition Mode

```bash
# Start monitoring at beginning of competition
sudo ./linux/blue_agent.sh monitor &

# In another terminal, watch for alerts
tail -f logs/blue_agent.log | grep "🚨\|⚠️"

# When alerts appear, investigate and remediate
sudo ./linux/blue_agent.sh scan
sudo ./linux/blue_agent.sh harden
```

---

## Performance Impact

### Resource Usage

| Metric | Impact |
|--------|--------|
| **CPU** | <1% average (spikes to 2-3% during checks) |
| **Memory** | ~10-20 MB |
| **Disk I/O** | Minimal (logs only) |
| **Network** | None (local only) |

### Scalability

- **Small systems** (1-2 cores): Use 15-30 second intervals
- **Medium systems** (4+ cores): Use 10 second intervals
- **Large systems** (8+ cores): Use 5 second intervals

---

## Troubleshooting

### Monitor Won't Start

**Problem:** "Monitoring already running"

**Solution:**
```bash
sudo ./linux/blue_agent.sh monitor stop
# Wait 2 seconds
sudo ./linux/blue_agent.sh monitor
```

### Stale PID File

**Problem:** Monitor not running but status shows PID

**Solution:** The tool auto-cleans stale PIDs. Just run:
```bash
sudo ./linux/blue_agent.sh monitor status
# It will detect and clean the stale PID
```

### Too Many Alerts

**Problem:** Monitor floods logs with user account alerts

**Solution:** This happens on first run when creating baseline. These are existing users being cataloged. Wait for one full check cycle (10 seconds) and alerts will stop.

To rebuild baselines:
```bash
rm -rf logs/monitor/
sudo ./linux/blue_agent.sh monitor --duration 20
```

### Missing Alerts

**Problem:** Monitor doesn't detect changes

**Solution:** Check that monitor is actually running:
```bash
sudo ./linux/blue_agent.sh monitor status
```

Ensure files being monitored exist in the baseline:
```bash
cat logs/monitor/file_integrity.db
```

---

## Advanced Features

### Custom Alert Actions

You can extend the monitor to trigger custom actions on alerts. Edit functions to add:

```bash
# Example: Send email on critical alert
check_file_integrity() {
    # ... existing code ...
    if [ "$current_hash" != "$expected_hash" ]; then
        log "🚨 [MONITOR] ALERT: File integrity violation detected: $filepath"
        
        # Custom action: Send alert
        echo "Critical file changed: $filepath" | mail -s "Security Alert" admin@example.com
    fi
}
```

### Integration with External Tools

**Example: Trigger incident response script**
```bash
check_suid_changes() {
    # ... existing code ...
    if [ -n "$suid_files" ]; then
        # Trigger IR script
        /path/to/incident_response.sh --alert suid_detected --file "$file"
    fi
}
```

---

## Competition Tips

### Pre-Competition Setup

1. **Create Clean Baselines**
   ```bash
   sudo ./linux/blue_agent.sh monitor --duration 20
   # Let it run one full cycle to create baselines
   sudo ./linux/blue_agent.sh monitor stop
   ```

2. **Test Alert Detection**
   ```bash
   # Create test SUID file
   sudo touch /tmp/test && sudo chmod u+s /tmp/test
   
   # Start monitor
   sudo ./linux/blue_agent.sh monitor --duration 30
   
   # Wait 15 seconds, check logs
   grep "🚨" logs/blue_agent.log
   
   # Clean up
   sudo rm /tmp/test
   ```

3. **Set Up Alert Monitoring**
   ```bash
   # Terminal window for alerts
   tail -f logs/blue_agent.log | grep --color -E "ALERT|🚨|⚠️"
   ```

### During Competition

1. **Start monitoring immediately:**
   ```bash
   sudo ./linux/blue_agent.sh monitor &
   ```

2. **Keep alert terminal visible** to catch real-time threats

3. **When alert appears:**
   - Note the type (SUID, process, network, etc.)
   - Run scan: `sudo ./linux/blue_agent.sh scan`
   - Review findings
   - Run harden: `sudo ./linux/blue_agent.sh harden`
   - Verify with re-scan

4. **Stop monitoring before end:**
   ```bash
   sudo ./linux/blue_agent.sh monitor stop
   ```

---

## Limitations

1. **Not a Full IDS/IPS**
   - The monitor is designed for rapid detection, not comprehensive intrusion prevention
   - Consider it a "first alert" system

2. **Baseline Dependency**
   - Effectiveness depends on clean initial baselines
   - If red team plants backdoors before monitoring starts, they won't be detected

3. **Local Only**
   - Does not monitor remote systems
   - Each system needs its own monitor instance

4. **No Historical Analysis**
   - Monitors current state vs. baseline
   - Does not perform long-term trend analysis

---

## Best Practices

### ✅ DO:
- Start monitoring at the beginning of competition
- Keep alert terminal visible
- Create clean baselines on known-good system state
- Investigate all alerts immediately
- Stop monitoring gracefully before end

### ❌ DON'T:
- Run multiple monitor instances simultaneously
- Ignore warnings (they may indicate real threats)
- Set check interval too low (<5 seconds)
- Create baselines while red team is active
- Forget to stop monitoring before leaving

---

## Future Enhancements

Potential improvements for future versions:

- [ ] inotify integration for instant file change detection
- [ ] Machine learning for anomaly detection
- [ ] Multi-system dashboard
- [ ] Email/SMS alert integration
- [ ] Automatic remediation triggers
- [ ] Historical trend analysis
- [ ] Custom rule engine
- [ ] Integration with SIEM systems

---

## Summary

The Monitor Module provides **real-time threat detection** across 5 critical security domains:

- ✅ File Integrity
- ✅ Process Monitoring
- ✅ Network Activity
- ✅ User Activity
- ✅ SUID/SGID Changes

**Perfect for:**
- Competition environments requiring rapid threat detection
- Real-time security monitoring during incident response
- Continuous security awareness in hardened systems

**Monitor Motto:** *"Sleep is for systems that aren't watching."* 👁️🛡️

---

**Need Help?**
- View logs: `cat logs/blue_agent.log | grep MONITOR`
- Check status: `sudo ./linux/blue_agent.sh monitor status`
- Stop monitor: `sudo ./linux/blue_agent.sh monitor stop`

**Ready to start monitoring? Run:** `sudo ./linux/blue_agent.sh monitor`
