#!/bin/bash
#
# CEG Blue Team Automation and Infrastructure Hardening Agent
#
# This script provides a modular framework for automating blue team tasks
# during the CyberEXPERT Game 2025. It focuses on rapid vulnerability
# identification and remediation without disrupting critical services.
#
# Usage: ./blue_agent.sh <module> [options]
#
# Modules:
#   - scan: Perform system-wide scans for common vulnerabilities.
#   - harden: Apply automated fixes for identified issues.
#   - monitor: Continuously watch for suspicious activity.
#   - report: Generate a summary of findings and actions.
#

# --- Configuration ---
CONFIG_DIR="$(dirname "$0")/../config"
LOG_DIR="$(dirname "$0")/../logs"
LOG_FILE="$LOG_DIR/blue_agent.log"
REPORT_DIR="/home/goodlife/Desktop/CEG25/reports"
SUID_BASELINE_FILE="$CONFIG_DIR/suid_baseline.conf"
USER_BASELINE_FILE="$CONFIG_DIR/user_baseline.conf"
EXCLUSION_IPS=("10.83.171.142" "rt01.core.i-isp.eu" "rt02.core.i-isp.eu" "rt03.core.i-isp.eu")
EXCLUSION_PORTS=("54321")

# --- Helper Functions ---
log() {
    # Ensure the log directory exists
    mkdir -p "$LOG_DIR"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

is_excluded_ip() {
    local ip=$1
    for excluded_ip in "${EXCLUSION_IPS[@]}"; do
        if [[ "$ip" == "$excluded_ip" ]]; then
            return 0
        fi
    done
    # Check for .253 in the last octet
    if [[ "$ip" == *".253" ]]; then
        return 0
    fi
    return 1
}

is_excluded_port() {
    local port=$1
    for excluded_port in "${EXCLUSION_PORTS[@]}"; do
        if [[ "$port" == "$excluded_port" ]]; then
            return 0
        fi
    done
    return 1
}

# --- Modules ---

scan_suid_sgid_files() {
    log "Scanning for SUID/SGID files..."
    local findings_log="${LOG_FILE}.suid_sgid_findings"
    local suspicious_files_log="${LOG_FILE}.suid_sgid_suspicious"
    
    # Create the baseline file if it doesn't exist
    if [ ! -f "$SUID_BASELINE_FILE" ]; then
        log "SUID baseline file not found. Creating one from current system state."
        # Find all SUID/SGID files and store their paths in the baseline file
        find / -type f \( -perm -4000 -o -perm -2000 \) -not \( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" \) -exec realpath {} \; 2>/dev/null > "$SUID_BASELINE_FILE"
        log "Baseline created at $SUID_BASELINE_FILE"
        return
    fi
    
    # Find all current SUID/SGID files
    find / -type f \( -perm -4000 -o -perm -2000 \) -not \( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" \) -exec realpath {} \; 2>/dev/null > "$findings_log"
    
    # Compare the current findings against the baseline
    grep -Fxvf "$SUID_BASELINE_FILE" "$findings_log" > "$suspicious_files_log"
    
    if [ -s "$suspicious_files_log" ]; then
        log "Found SUSPICIOUS SUID/SGID files (not in baseline):"
        while IFS= read -r file_path; do
            ls -l "$file_path" >> "$LOG_FILE"
        done < "$suspicious_files_log"
    else
        log "No suspicious SUID/SGID files found."
    fi
    
    # Clean up temporary files
    rm -f "$findings_log"
}

scan_world_writable_files() {
    log "Scanning for world-writable files and directories..."
    local findings_log="${LOG_FILE}.world_writable_findings"
    
    # Find world-writable files and directories, excluding system/proc paths and symlinks
    find / -not \( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" \) -not -path "/run/*" \( -type f -o -type d \) -perm -o+w -exec ls -ld {} \; 2>/dev/null > "$findings_log"
    
    if [ -s "$findings_log" ]; then
        log "Found world-writable files/directories:"
        cat "$findings_log" >> "$LOG_FILE"
    else
        log "No world-writable files/directories found."
    fi
    
    # We keep the findings log for the harden module to use
    # rm -f "$findings_log"
}

scan_listening_ports() {
    log "Scanning for listening ports..."
    local findings_log="${LOG_FILE}.listening_ports_findings"
    
    # Use ss to find listening TCP and UDP ports, get the port number
    ss -tuln | awk 'NR>1 {print $5}' | awk -F: '{print $NF}' | sort -un > "$findings_log"
    
    local suspicious_ports=0
    while IFS= read -r port; do
        if ! is_excluded_port "$port"; then
            if [ "$suspicious_ports" -eq 0 ]; then
                log "Found potentially unauthorized listening ports:"
                suspicious_ports=1
            fi
            log "  - Port: $port"
        fi
    done < "$findings_log"
    
    if [ "$suspicious_ports" -eq 0 ]; then
        log "No suspicious listening ports found."
    fi
    
    rm -f "$findings_log"
}

scan_excessive_users() {
    log "Scanning for excessive users..."
    local current_users_log="${LOG_FILE}.current_users"
    local suspicious_users_log="${LOG_FILE}.suspicious_users"
    
    # Create user baseline if it doesn't exist
    if [ ! -f "$USER_BASELINE_FILE" ]; then
        log "User baseline file not found. Creating one from current system state."
        awk -F: '{print $1}' /etc/passwd > "$USER_BASELINE_FILE"
        log "User baseline created at $USER_BASELINE_FILE"
        return
    fi
    
    # Get current users
    awk -F: '{print $1}' /etc/passwd > "$current_users_log"
    
    # Compare current users against the baseline
    grep -Fxvf "$USER_BASELINE_FILE" "$current_users_log" > "$suspicious_users_log"
    
    if [ -s "$suspicious_users_log" ]; then
        log "Found SUSPICIOUS users (not in baseline):"
        cat "$suspicious_users_log" >> "$LOG_FILE"
    else
        log "No suspicious users found."
    fi
    
    rm -f "$current_users_log"
}

scan_weak_passwords() {
    log "Scanning for weak passwords..."
    local unshadowed_file="${LOG_DIR}/unshadowed.txt"
    local pot_file="${LOG_DIR}/john.pot"
    local weak_pass_list="$CONFIG_DIR/weak_passwords.txt"

    # Check if john is installed
    if ! command -v john &> /dev/null; then
        log "John the Ripper is not installed. Skipping weak password scan."
        return
    fi

    # Create the unshadowed file (requires sudo)
    log "Creating unshadowed password file..."
    sudo unshadow /etc/passwd /etc/shadow > "$unshadowed_file" 2>/dev/null
    if [ $? -ne 0 ]; then
        log "Failed to create unshadowed file. Make sure you have sudo privileges."
        rm -f "$unshadowed_file"
        return
    fi

    log "Running John the Ripper against password hashes..."
    # Run john with the wordlist
    sudo john --wordlist="$weak_pass_list" --pot="$pot_file" "$unshadowed_file" >/dev/null 2>&1

    # Ensure the pot file is readable by the script
    if [ -f "$pot_file" ]; then
        sudo chown "$(whoami)" "$pot_file"
    fi

    # Check the pot file for cracked passwords
    if [ -f "$pot_file" ]; then
        # The pot file format is $HASH:PASSWORD
        # We want to match the hash with the user in the unshadowed file
        log "Checking for cracked passwords..."
        
        # Clear previous findings
        > "${LOG_FILE}.weak_pass_findings"

        while IFS=: read -r hash pass; do
            # Find the user associated with this hash
            user=$(grep "^[^:]*:$hash:" "$unshadowed_file" | cut -d: -f1)
            if [ -n "$user" ]; then
                echo "User: '$user' has a weak password: '$pass'" >> "${LOG_FILE}.weak_pass_findings"
            fi
        done < "$pot_file"

        if [ -s "${LOG_FILE}.weak_pass_findings" ]; then
            log "Found users with weak passwords:"
            cat "${LOG_FILE}.weak_pass_findings" >> "$LOG_FILE"
        else
            log "No weak passwords found."
        fi
        rm -f "${LOG_FILE}.weak_pass_findings"
    else
        log "No weak passwords found."
    fi

    # Cleanup
    rm -f "$unshadowed_file"
    # We keep the pot file so we don't re-crack the same passwords
}

scan_ssh_config() {
    log "Scanning SSH configuration..."
    local ssh_config="/etc/ssh/sshd_config"
    local findings_log="${LOG_FILE}.ssh_findings"
    
    if [ ! -f "$ssh_config" ]; then
        log "SSH configuration file not found. SSH may not be installed."
        return
    fi
    
    > "$findings_log"
    local issues_found=0
    
    # Check for PermitRootLogin
    if grep -q "^PermitRootLogin yes" "$ssh_config" 2>/dev/null; then
        echo "⚠️  Root login is ENABLED (PermitRootLogin yes)" >> "$findings_log"
        issues_found=1
    fi
    
    # Check for PasswordAuthentication
    if grep -q "^PasswordAuthentication yes" "$ssh_config" 2>/dev/null; then
        echo "⚠️  Password authentication is ENABLED (should use key-based auth)" >> "$findings_log"
        issues_found=1
    fi
    
    # Check for PermitEmptyPasswords
    if grep -q "^PermitEmptyPasswords yes" "$ssh_config" 2>/dev/null; then
        echo "🚨 CRITICAL: Empty passwords are ALLOWED" >> "$findings_log"
        issues_found=1
    fi
    
    # Check for Protocol version (if specified)
    if grep -q "^Protocol 1" "$ssh_config" 2>/dev/null; then
        echo "🚨 CRITICAL: Using insecure SSH Protocol 1" >> "$findings_log"
        issues_found=1
    fi
    
    # Check X11Forwarding
    if grep -q "^X11Forwarding yes" "$ssh_config" 2>/dev/null; then
        echo "⚠️  X11 Forwarding is enabled (potential security risk)" >> "$findings_log"
        issues_found=1
    fi
    
    # Check if MaxAuthTries is too high
    max_auth=$(grep "^MaxAuthTries" "$ssh_config" 2>/dev/null | awk '{print $2}')
    if [ -n "$max_auth" ] && [ "$max_auth" -gt 4 ]; then
        echo "⚠️  MaxAuthTries is set to $max_auth (recommended: 4 or less)" >> "$findings_log"
        issues_found=1
    fi
    
    if [ "$issues_found" -eq 1 ]; then
        log "Found SSH configuration issues:"
        cat "$findings_log" >> "$LOG_FILE"
    else
        log "SSH configuration appears secure."
    fi
    
    rm -f "$findings_log"
}

scan_firewall_rules() {
    log "Scanning firewall configuration..."
    local findings_log="${LOG_FILE}.firewall_findings"
    
    > "$findings_log"
    local issues_found=0
    
    # Check if ufw is installed and active
    if command -v ufw &> /dev/null; then
        local ufw_status=$(sudo ufw status 2>/dev/null | head -n 1)
        
        if echo "$ufw_status" | grep -qi "inactive"; then
            echo "🚨 CRITICAL: UFW firewall is INACTIVE" >> "$findings_log"
            issues_found=1
        else
            log "UFW Status: Active"
            
            # Check for overly permissive rules
            if sudo ufw status numbered 2>/dev/null | grep -qi "ALLOW.*Anywhere"; then
                echo "⚠️  Found potentially permissive firewall rules (ALLOW from Anywhere)" >> "$findings_log"
                issues_found=1
            fi
        fi
    elif command -v iptables &> /dev/null; then
        # Check iptables if ufw is not available
        local iptables_rules=$(sudo iptables -L -n 2>/dev/null | wc -l)
        
        if [ "$iptables_rules" -lt 5 ]; then
            echo "⚠️  IPTables has very few rules configured ($iptables_rules lines)" >> "$findings_log"
            issues_found=1
        fi
        
        # Check for default ACCEPT policy
        if sudo iptables -L -n 2>/dev/null | grep -q "Chain INPUT (policy ACCEPT)"; then
            echo "⚠️  IPTables INPUT chain has ACCEPT policy (should be DROP)" >> "$findings_log"
            issues_found=1
        fi
    else
        echo "⚠️  No firewall detected (neither UFW nor IPTables found)" >> "$findings_log"
        issues_found=1
    fi
    
    if [ "$issues_found" -eq 1 ]; then
        log "Found firewall configuration issues:"
        cat "$findings_log" >> "$LOG_FILE"
    else
        log "Firewall configuration appears secure."
    fi
    
    rm -f "$findings_log"
}

scan_docker_security() {
    log "Scanning Docker/container security..."
    local findings_log="${LOG_FILE}.docker_findings"
    
    if ! command -v docker &> /dev/null; then
        log "Docker is not installed. Skipping container security scan."
        return
    fi
    
    > "$findings_log"
    local issues_found=0
    
    # Check if Docker daemon is running
    if ! sudo docker info &>/dev/null; then
        log "Docker daemon is not running. Skipping container security scan."
        return
    fi
    
    # Check for privileged containers
    local priv_containers=$(sudo docker ps --quiet --all --filter "status=running" 2>/dev/null | \
        xargs -r sudo docker inspect --format '{{.Name}}:{{.HostConfig.Privileged}}' 2>/dev/null | \
        grep ":true" | cut -d: -f1)
    
    if [ -n "$priv_containers" ]; then
        echo "🚨 CRITICAL: Found privileged containers running:" >> "$findings_log"
        echo "$priv_containers" | while read container; do
            echo "  - $container" >> "$findings_log"
        done
        issues_found=1
    fi
    
    # Check for containers running as root
    local root_containers=$(sudo docker ps --quiet --all --filter "status=running" 2>/dev/null | \
        xargs -r sudo docker inspect --format '{{.Name}}:{{.Config.User}}' 2>/dev/null | \
        grep ":$\|:0$\|:root$" | cut -d: -f1)
    
    if [ -n "$root_containers" ]; then
        echo "⚠️  Found containers running as root:" >> "$findings_log"
        echo "$root_containers" | while read container; do
            echo "  - $container" >> "$findings_log"
        done
        issues_found=1
    fi
    
    # Check for containers with host network mode
    local host_net_containers=$(sudo docker ps --quiet --all --filter "status=running" 2>/dev/null | \
        xargs -r sudo docker inspect --format '{{.Name}}:{{.HostConfig.NetworkMode}}' 2>/dev/null | \
        grep ":host$" | cut -d: -f1)
    
    if [ -n "$host_net_containers" ]; then
        echo "⚠️  Found containers using host network mode:" >> "$findings_log"
        echo "$host_net_containers" | while read container; do
            echo "  - $container" >> "$findings_log"
        done
        issues_found=1
    fi
    
    # Check for exposed Docker socket
    if [ -S "/var/run/docker.sock" ]; then
        local sock_perms=$(stat -c "%a" /var/run/docker.sock 2>/dev/null)
        if [ "$sock_perms" = "666" ] || [ "$sock_perms" = "777" ]; then
            echo "🚨 CRITICAL: Docker socket has overly permissive permissions ($sock_perms)" >> "$findings_log"
            issues_found=1
        fi
        
        # Check if socket is mounted in any container
        local socket_mounts=$(sudo docker ps --quiet --all --filter "status=running" 2>/dev/null | \
            xargs -r sudo docker inspect --format '{{.Name}}:{{range .Mounts}}{{.Source}}{{end}}' 2>/dev/null | \
            grep "docker.sock" | cut -d: -f1)
        
        if [ -n "$socket_mounts" ]; then
            echo "🚨 CRITICAL: Docker socket is mounted in containers:" >> "$findings_log"
            echo "$socket_mounts" | while read container; do
                echo "  - $container" >> "$findings_log"
            done
            issues_found=1
        fi
    fi
    
    if [ "$issues_found" -eq 1 ]; then
        log "Found Docker security issues:"
        cat "$findings_log" >> "$LOG_FILE"
    else
        log "Docker configuration appears secure."
    fi
    
    rm -f "$findings_log"
}

run_scan() {
    log "Starting system scan..."
    
    # Scan for SUID/SGID files
    scan_suid_sgid_files
    
    # Scan for world-writable files
    scan_world_writable_files
    
    # Scan for listening ports
    scan_listening_ports
    
    # Scan for excessive users
    scan_excessive_users

    # Scan for weak passwords
    scan_weak_passwords
    
    # Scan SSH configuration
    scan_ssh_config
    
    # Scan firewall rules
    scan_firewall_rules
    
    # Scan Docker/container security
    scan_docker_security
    
    log "Scan complete."
}

run_harden() {
    log "Starting system hardening..."
    
    # Harden suspicious SUID/SGID files
    local suspicious_files_log="${LOG_FILE}.suid_sgid_suspicious"
    if [ -f "$suspicious_files_log" ]; then
        log "Hardening suspicious SUID/SGID files..."
        while IFS= read -r file_path; do
            if [ -f "$file_path" ]; then
                log "Removing SUID/SGID bit from $file_path"
                # Use sudo for the actual remediation
                sudo chmod -s "$file_path"
            fi
        done < "$suspicious_files_log"
        rm -f "$suspicious_files_log"
    fi
    
    # Harden world-writable files and directories
    local world_writable_log="${LOG_FILE}.world_writable_findings"
    if [ -f "$world_writable_log" ]; then
        log "Hardening world-writable files/directories..."
        # Extract just the path from the 'ls -ld' output
        awk '{print $NF}' "$world_writable_log" | while IFS= read -r file_path; do
             if [ -e "$file_path" ]; then
                log "Removing world-writable permission from $file_path"
                sudo chmod o-w "$file_path"
            fi
        done
        rm -f "$world_writable_log"
    fi

    # Harden suspicious users
    local suspicious_users_log="${LOG_FILE}.suspicious_users"
    if [ -f "$suspicious_users_log" ]; then
        log "Hardening suspicious user accounts..."
        while IFS= read -r user; do
            if id "$user" &>/dev/null; then
                log "Locking account for suspicious user: $user"
                sudo usermod -L "$user"
            fi
        done < "$suspicious_users_log"
        rm -f "$suspicious_users_log"
    fi
    
    log "Hardening complete."
}

run_monitor() {
    # Configuration
    MONITOR_DIR="$LOG_DIR/monitor"
    MONITOR_INTERVAL=10  # seconds between checks
    MONITOR_PID_FILE="$MONITOR_DIR/monitor.pid"
    FILE_INTEGRITY_DB="$MONITOR_DIR/file_integrity.db"
    PROCESS_BASELINE="$MONITOR_DIR/process_baseline.txt"
    NETWORK_BASELINE="$MONITOR_DIR/network_baseline.txt"
    
    mkdir -p "$MONITOR_DIR"
    
    # Parse options first (before any logging)
    DURATION=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --duration)
                DURATION="$2"
                shift 2
                ;;
            stop)
                stop_monitor
                return 0
                ;;
            status)
                monitor_status
                return 0
                ;;
            *)
                echo "Unknown monitor option: $1"
                echo "Usage: $0 monitor [--duration <seconds>] | stop | status"
                return 1
                ;;
        esac
    done
    
    # Now log startup (after confirming we're actually starting)
    log "Starting continuous monitoring..."
    
    # Check if monitoring is already running
    if [ -f "$MONITOR_PID_FILE" ]; then
        old_pid=$(cat "$MONITOR_PID_FILE")
        if ps -p "$old_pid" > /dev/null 2>&1; then
            log "Monitoring already running with PID $old_pid"
            echo "Monitor is already running. Use 'stop' to stop it first."
            return 1
        else
            log "Removing stale PID file"
            rm -f "$MONITOR_PID_FILE"
        fi
    fi
    
    # Initialize baselines if they don't exist
    if [ ! -f "$FILE_INTEGRITY_DB" ]; then
        log "Creating file integrity baseline..."
        create_file_integrity_baseline
    fi
    
    if [ ! -f "$PROCESS_BASELINE" ]; then
        log "Creating process baseline..."
        ps aux | sort > "$PROCESS_BASELINE"
    fi
    
    if [ ! -f "$NETWORK_BASELINE" ]; then
        log "Creating network baseline..."
        ss -tulpn | sort > "$NETWORK_BASELINE"
    fi
    
    # Start monitoring in background
    monitor_loop "$DURATION" &
    MONITOR_PID=$!
    echo "$MONITOR_PID" > "$MONITOR_PID_FILE"
    
    log "Monitoring started with PID $MONITOR_PID"
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║              Real-Time Monitoring ACTIVE                       ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Monitor PID: $MONITOR_PID"
    echo "  Check Interval: ${MONITOR_INTERVAL}s"
    echo "  Logs: $LOG_FILE"
    echo ""
    echo "  Commands:"
    echo "    Stop:   sudo $0 monitor stop"
    echo "    Status: sudo $0 monitor status"
    echo "    Logs:   tail -f $LOG_FILE | grep MONITOR"
    echo ""
    
    if [ -n "$DURATION" ]; then
        echo "  Will run for $DURATION seconds"
        echo ""
    else
        echo "  Running indefinitely (use 'stop' to terminate)"
        echo ""
    fi
}

stop_monitor() {
    if [ ! -f "$MONITOR_PID_FILE" ]; then
        log "No monitoring process found"
        echo "Monitor is not running."
        return 1
    fi
    
    monitor_pid=$(cat "$MONITOR_PID_FILE")
    if ps -p "$monitor_pid" > /dev/null 2>&1; then
        log "Stopping monitoring (PID $monitor_pid)..."
        kill "$monitor_pid" 2>/dev/null
        rm -f "$MONITOR_PID_FILE"
        log "Monitoring stopped."
        echo "✓ Monitor stopped successfully."
    else
        log "Monitor process not found (stale PID file)"
        rm -f "$MONITOR_PID_FILE"
        echo "Monitor was not running (cleaned up stale PID file)."
    fi
}

monitor_status() {
    MONITOR_DIR="$LOG_DIR/monitor"
    MONITOR_PID_FILE="$MONITOR_DIR/monitor.pid"
    
    if [ ! -f "$MONITOR_PID_FILE" ]; then
        echo "Status: NOT RUNNING"
        return 1
    fi
    
    monitor_pid=$(cat "$MONITOR_PID_FILE")
    if ps -p "$monitor_pid" > /dev/null 2>&1; then
        runtime=$(ps -o etime= -p "$monitor_pid" | tr -d ' ')
        echo "Status: RUNNING"
        echo "PID: $monitor_pid"
        echo "Runtime: $runtime"
        echo "Logs: $LOG_FILE"
        
        # Show recent alerts
        echo ""
        echo "Recent Alerts (last 10):"
        echo "────────────────────────────────────────────────────────"
        grep "⚠️\|🚨\|ALERT\|MONITOR" "$LOG_FILE" | tail -10
        return 0
    else
        echo "Status: NOT RUNNING (stale PID file)"
        rm -f "$MONITOR_PID_FILE"
        return 1
    fi
}

create_file_integrity_baseline() {
    # Create checksums for critical system files
    CRITICAL_PATHS=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/sudoers"
        "/etc/ssh/sshd_config"
        "/etc/hosts"
        "/etc/crontab"
        "/root/.ssh/authorized_keys"
    )
    
    > "$FILE_INTEGRITY_DB"
    
    for path in "${CRITICAL_PATHS[@]}"; do
        if [ -f "$path" ]; then
            checksum=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
            echo "$path:$checksum" >> "$FILE_INTEGRITY_DB"
        fi
    done
    
    log "File integrity baseline created with ${#CRITICAL_PATHS[@]} files"
}

monitor_loop() {
    local duration=$1
    local start_time=$(date +%s)
    local check_count=0
    
    log "[MONITOR] Monitoring loop started"
    
    while true; do
        check_count=$((check_count + 1))
        
        # Check if duration limit reached
        if [ -n "$duration" ]; then
            current_time=$(date +%s)
            elapsed=$((current_time - start_time))
            if [ "$elapsed" -ge "$duration" ]; then
                log "[MONITOR] Duration limit reached ($duration seconds). Stopping."
                rm -f "$MONITOR_PID_FILE"
                break
            fi
        fi
        
        # File Integrity Check
        check_file_integrity
        
        # Process Monitoring
        check_suspicious_processes
        
        # Network Monitoring
        check_network_connections
        
        # User Activity Monitoring
        check_user_activity
        
        # SUID/SGID Change Detection
        check_suid_changes
        
        sleep "$MONITOR_INTERVAL"
    done
    
    log "[MONITOR] Monitoring loop ended after $check_count checks"
}

check_file_integrity() {
    while IFS=: read -r filepath expected_hash; do
        if [ -f "$filepath" ]; then
            current_hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
            if [ "$current_hash" != "$expected_hash" ]; then
                log "🚨 [MONITOR] ALERT: File integrity violation detected: $filepath"
                log "[MONITOR] Expected: $expected_hash, Got: $current_hash"
                
                # Update baseline with new hash
                sed -i "s|$filepath:.*|$filepath:$current_hash|" "$FILE_INTEGRITY_DB"
            fi
        else
            log "⚠️ [MONITOR] WARNING: Critical file missing: $filepath"
        fi
    done < "$FILE_INTEGRITY_DB"
}

check_suspicious_processes() {
    # Look for new processes not in baseline
    current_processes=$(ps aux | awk '{print $11}' | sort -u)
    baseline_processes=$(cat "$PROCESS_BASELINE" | awk '{print $11}' | sort -u)
    
    # Common suspicious process names
    SUSPICIOUS_PATTERNS=(
        "nc -l"
        "ncat -l"
        "socat"
        "python.*SimpleHTTPServer"
        "python.*-m http.server"
        "perl.*reverse"
        "bash -i"
        "sh -i"
        "/tmp/"
        "/dev/shm/"
    )
    
    # Check for suspicious patterns
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if ps aux | grep -v grep | grep -q "$pattern"; then
            suspicious_proc=$(ps aux | grep -v grep | grep "$pattern")
            log "🚨 [MONITOR] ALERT: Suspicious process detected: $pattern"
            log "[MONITOR] Details: $suspicious_proc"
        fi
    done
    
    # Check for processes running from /tmp or /dev/shm
    ps aux | grep -E '/tmp/|/dev/shm/' | grep -v grep | while read -r line; do
        log "⚠️ [MONITOR] WARNING: Process running from temporary directory: $line"
    done
}

check_network_connections() {
    # Check for new listening ports
    current_ports=$(ss -tulpn 2>/dev/null | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -u)
    
    # Compare with baseline
    for port in $current_ports; do
        if ! grep -q ":$port" "$NETWORK_BASELINE" 2>/dev/null; then
            process_info=$(ss -tulpn 2>/dev/null | grep ":$port" | head -1)
            log "⚠️ [MONITOR] ALERT: New listening port detected: $port"
            log "[MONITOR] Details: $process_info"
        fi
    done
    
    # Check for suspicious outbound connections
    suspicious_ips=$(ss -tnp 2>/dev/null | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort -u)
    
    # Look for connections to suspicious ports (common C2 ports)
    SUSPICIOUS_PORTS=(4444 4445 5555 6666 7777 8888 9999 31337 1337)
    
    for port in "${SUSPICIOUS_PORTS[@]}"; do
        if ss -tn 2>/dev/null | grep ESTAB | grep -q ":$port"; then
            connection=$(ss -tnp 2>/dev/null | grep ESTAB | grep ":$port")
            log "🚨 [MONITOR] ALERT: Suspicious outbound connection to port $port"
            log "[MONITOR] Details: $connection"
        fi
    done
}

check_user_activity() {
    # Check for new logins
    current_users=$(who | awk '{print $1}' | sort -u)
    
    # Check for users logged in from remote IPs
    who | grep -v 'tty' | while read -r line; do
        username=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $5}' | tr -d '()')
        
        if [ -n "$ip" ] && [ "$ip" != ":0" ]; then
            log "ℹ️ [MONITOR] INFO: Remote login detected - User: $username from IP: $ip"
        fi
    done
    
    # Check for failed login attempts
    failed_logins=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5)
    if [ -n "$failed_logins" ]; then
        count=$(echo "$failed_logins" | wc -l)
        log "⚠️ [MONITOR] WARNING: $count recent failed login attempts detected"
    fi
    
    # Check for new user accounts
    if [ -f "$USER_BASELINE_FILE" ]; then
        current_users_file="/tmp/current_users_$$.txt"
        cut -d: -f1 /etc/passwd | sort > "$current_users_file"
        
        new_users=$(comm -13 "$USER_BASELINE_FILE" "$current_users_file")
        if [ -n "$new_users" ]; then
            log "🚨 [MONITOR] ALERT: New user account(s) created:"
            echo "$new_users" | while read -r user; do
                log "[MONITOR] - $user"
            done
        fi
        
        rm -f "$current_users_file"
    fi
}

check_suid_changes() {
    # Quick check for SUID changes (sample key directories)
    SUID_CHECK_DIRS=(
        "/tmp"
        "/var/tmp"
        "/dev/shm"
        "/home"
    )
    
    for dir in "${SUID_CHECK_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            suid_files=$(find "$dir" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
            if [ -n "$suid_files" ]; then
                echo "$suid_files" | while read -r file; do
                    log "🚨 [MONITOR] ALERT: SUID/SGID file detected in suspicious location: $file"
                done
            fi
        fi
    done
}

run_report() {
    log "Generating report..."
    
    if [ ! -d "$REPORT_DIR" ]; then
        mkdir -p "$REPORT_DIR"
    fi
    
    report_file="$REPORT_DIR/report_$(date +'%Y%m%d_%H%M%S').txt"
    
    # Header
    cat > "$report_file" << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CEG Blue Team Agent Security Report                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    
    echo "" >> "$report_file"
    echo "Generated on: $(date '+%Y-%m-%d %H:%M:%S')" >> "$report_file"
    echo "Hostname: $(hostname)" >> "$report_file"
    echo "System: $(uname -s) $(uname -r)" >> "$report_file"
    echo "" >> "$report_file"
    echo "════════════════════════════════════════════════════════════════════════════════" >> "$report_file"
    
    # SUID/SGID Findings
    echo "" >> "$report_file"
    echo "📋 SUID/SGID File Scan Results" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    suid_count=$(grep -c "Found SUSPICIOUS SUID/SGID files" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$suid_count" -gt 0 ]; then
        echo "⚠️  Status: SUSPICIOUS FILES DETECTED" >> "$report_file"
        grep -A 20 "Found SUSPICIOUS SUID/SGID files" "$LOG_FILE" | tail -n +2 | head -n 20 >> "$report_file" 2>/dev/null
    else
        echo "✅ Status: No suspicious SUID/SGID files found" >> "$report_file"
    fi
    
    # World-Writable Files
    echo "" >> "$report_file"
    echo "📋 World-Writable Files Scan Results" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    ww_count=$(grep -c "Found world-writable files/directories" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$ww_count" -gt 0 ]; then
        echo "⚠️  Status: WORLD-WRITABLE FILES DETECTED" >> "$report_file"
        echo "Note: Excessive output may be truncated. Check logs for complete list." >> "$report_file"
        grep -A 10 "Found world-writable files/directories" "$LOG_FILE" | tail -n +2 | head -n 10 >> "$report_file" 2>/dev/null
    else
        echo "✅ Status: No world-writable files found" >> "$report_file"
    fi
    
    # Listening Ports
    echo "" >> "$report_file"
    echo "📋 Listening Ports Scan Results" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    port_count=$(grep -c "potentially unauthorized listening ports" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$port_count" -gt 0 ]; then
        echo "⚠️  Status: SUSPICIOUS PORTS DETECTED" >> "$report_file"
        grep "  - Port:" "$LOG_FILE" | tail -n 20 >> "$report_file" 2>/dev/null
    else
        echo "✅ Status: No suspicious listening ports found" >> "$report_file"
    fi
    
    # Excessive Users
    echo "" >> "$report_file"
    echo "📋 User Account Scan Results" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    user_count=$(grep -c "Found SUSPICIOUS users" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$user_count" -gt 0 ]; then
        echo "⚠️  Status: SUSPICIOUS USERS DETECTED" >> "$report_file"
        grep -A 10 "Found SUSPICIOUS users" "$LOG_FILE" | tail -n +2 | head -n 10 >> "$report_file" 2>/dev/null
    else
        echo "✅ Status: No suspicious users found" >> "$report_file"
    fi
    
    # Weak Passwords
    echo "" >> "$report_file"
    echo "📋 Weak Password Scan Results" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    weak_pass_count=$(grep -c "Found users with weak passwords" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$weak_pass_count" -gt 0 ]; then
        echo "🚨 Status: WEAK PASSWORDS DETECTED" >> "$report_file"
        grep "User:.*has a weak password:" "$LOG_FILE" | tail -n 10 >> "$report_file" 2>/dev/null
    else
        echo "✅ Status: No weak passwords found" >> "$report_file"
    fi
    
    # SSH Configuration
    echo "" >> "$report_file"
    echo "📋 SSH Configuration Audit Results" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    ssh_issues=$(grep -c "Found SSH configuration issues" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$ssh_issues" -gt 0 ]; then
        echo "⚠️  Status: SSH CONFIGURATION ISSUES DETECTED" >> "$report_file"
        grep "⚠️\|🚨" "$LOG_FILE" | grep -A1 "Found SSH configuration issues" | tail -n 10 >> "$report_file" 2>/dev/null
    else
        ssh_secure=$(grep -c "SSH configuration appears secure" "$LOG_FILE" 2>/dev/null || echo "0")
        if [ "$ssh_secure" -gt 0 ]; then
            echo "✅ Status: SSH configuration appears secure" >> "$report_file"
        else
            echo "ℹ️  Status: SSH not configured or scan not performed" >> "$report_file"
        fi
    fi
    
    # Firewall Rules
    echo "" >> "$report_file"
    echo "📋 Firewall Configuration Audit Results" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    fw_issues=$(grep -c "Found firewall configuration issues" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$fw_issues" -gt 0 ]; then
        echo "⚠️  Status: FIREWALL ISSUES DETECTED" >> "$report_file"
        grep "⚠️\|🚨" "$LOG_FILE" | grep -A1 "Found firewall configuration issues" | tail -n 10 >> "$report_file" 2>/dev/null
    else
        fw_secure=$(grep -c "Firewall configuration appears secure" "$LOG_FILE" 2>/dev/null || echo "0")
        if [ "$fw_secure" -gt 0 ]; then
            echo "✅ Status: Firewall configuration appears secure" >> "$report_file"
        else
            echo "ℹ️  Status: Firewall scan not performed" >> "$report_file"
        fi
    fi
    
    # Docker Security
    echo "" >> "$report_file"
    echo "📋 Docker/Container Security Audit Results" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    docker_issues=$(grep -c "Found Docker security issues" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$docker_issues" -gt 0 ]; then
        echo "🚨 Status: DOCKER SECURITY ISSUES DETECTED" >> "$report_file"
        grep "⚠️\|🚨" "$LOG_FILE" | grep -A1 "Found Docker security issues" | tail -n 15 >> "$report_file" 2>/dev/null
    else
        docker_secure=$(grep -c "Docker configuration appears secure" "$LOG_FILE" 2>/dev/null || echo "0")
        if [ "$docker_secure" -gt 0 ]; then
            echo "✅ Status: Docker configuration appears secure" >> "$report_file"
        else
            echo "ℹ️  Status: Docker not installed or scan not performed" >> "$report_file"
        fi
    fi
    
    # Hardening Actions
    echo "" >> "$report_file"
    echo "════════════════════════════════════════════════════════════════════════════════" >> "$report_file"
    echo "" >> "$report_file"
    echo "🔧 Hardening Actions Taken" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    
    harden_count=$(grep -c "Starting system hardening" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$harden_count" -gt 0 ]; then
        echo "Actions performed:" >> "$report_file"
        grep "Removing SUID/SGID bit from\|Removing world-writable permission from\|Locking account for suspicious user" "$LOG_FILE" | tail -n 20 >> "$report_file" 2>/dev/null
    else
        echo "No hardening actions have been performed yet." >> "$report_file"
    fi
    
    # Summary Statistics
    echo "" >> "$report_file"
    echo "════════════════════════════════════════════════════════════════════════════════" >> "$report_file"
    echo "" >> "$report_file"
    echo "📊 Summary Statistics" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    
    total_scans=$(grep -c "Starting system scan" "$LOG_FILE" 2>/dev/null || echo "0")
    total_hardenings=$(grep -c "Starting system hardening" "$LOG_FILE" 2>/dev/null || echo "0")
    
    echo "Total Scans Performed: $total_scans" >> "$report_file"
    echo "Total Hardening Operations: $total_hardenings" >> "$report_file"
    
    # Recommendations
    echo "" >> "$report_file"
    echo "════════════════════════════════════════════════════════════════════════════════" >> "$report_file"
    echo "" >> "$report_file"
    echo "💡 Recommendations" >> "$report_file"
    echo "────────────────────────────────────────────────────────────────────────────────" >> "$report_file"
    
    if [ "$suid_count" -gt 0 ]; then
        echo "• Review and remove suspicious SUID/SGID files" >> "$report_file"
    fi
    if [ "$ww_count" -gt 0 ]; then
        echo "• Investigate world-writable files and correct permissions" >> "$report_file"
    fi
    if [ "$port_count" -gt 0 ]; then
        echo "• Review unauthorized listening ports and terminate suspicious services" >> "$report_file"
    fi
    if [ "$user_count" -gt 0 ]; then
        echo "• Investigate and remove unauthorized user accounts" >> "$report_file"
    fi
    if [ "$weak_pass_count" -gt 0 ]; then
        echo "🚨 CRITICAL: Force password changes for users with weak passwords immediately!" >> "$report_file"
    fi
    if [ "$ssh_issues" -gt 0 ]; then
        echo "• Review and harden SSH configuration (/etc/ssh/sshd_config)" >> "$report_file"
    fi
    if [ "$fw_issues" -gt 0 ]; then
        echo "• Review and strengthen firewall rules" >> "$report_file"
    fi
    if [ "$docker_issues" -gt 0 ]; then
        echo "🚨 CRITICAL: Address Docker security vulnerabilities immediately!" >> "$report_file"
    fi
    
    if [ "$suid_count" -eq 0 ] && [ "$ww_count" -eq 0 ] && [ "$port_count" -eq 0 ] && [ "$user_count" -eq 0 ] && [ "$weak_pass_count" -eq 0 ] && [ "$ssh_issues" -eq 0 ] && [ "$fw_issues" -eq 0 ] && [ "$docker_issues" -eq 0 ]; then
        echo "✅ No immediate security concerns detected. Continue regular monitoring." >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "════════════════════════════════════════════════════════════════════════════════" >> "$report_file"
    echo "" >> "$report_file"
    echo "Full logs available at: $LOG_FILE" >> "$report_file"
    echo "" >> "$report_file"
    
    log "Report generated at $report_file"
    
    # Also display the report to the terminal
    echo ""
    echo "Report Preview:"
    echo "════════════════════════════════════════════════════════════════════════════════"
    cat "$report_file"
}

# --- Main Logic ---
main() {
    if [ "$#" -eq 0 ]; then
        echo "Usage: $0 <module>"
        echo "Modules: scan, harden, monitor, report"
        exit 1
    fi
    
    module=$1
    shift
    
    case "$module" in
        scan)
            run_scan "$@"
            ;;
        harden)
            run_harden "$@"
            ;;
        monitor)
            run_monitor "$@"
            ;;
        report)
            run_report "$@"
            ;;
        *)
            echo "Unknown module: $module"
            exit 1
            ;;
    esac
}

main "$@"
