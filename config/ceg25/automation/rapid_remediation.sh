#!/bin/bash
# CEG25 Rapid Vulnerability Remediation

PHASE=$1
LOG_FILE="../logs/ceg25/rapid_remediation.log"

log_action() {
    echo "[$(date)] [$PHASE] $1" >> "$LOG_FILE"
}

# Fix common vulnerabilities rapidly
fix_common_vulnerabilities() {
    log_action "Starting rapid vulnerability remediation"
    
    # Default passwords
    log_action "Changing default passwords"
    echo "admin:$(openssl rand -base64 32)" | chpasswd 2>/dev/null
    echo "operator:$(openssl rand -base64 32)" | chpasswd 2>/dev/null
    echo "guest:$(openssl rand -base64 32)" | chpasswd 2>/dev/null
    
    # File permissions
    log_action "Securing file permissions"
    find /home -name "*.sh" -exec chmod 750 {} \; 2>/dev/null
    find /etc -name "*.conf" -exec chmod 644 {} \; 2>/dev/null
    
    # Remove unnecessary services
    log_action "Disabling unnecessary services"
    systemctl stop telnet xinetd rsh 2>/dev/null
    systemctl disable telnet xinetd rsh 2>/dev/null
    
    # Secure SSH
    log_action "Hardening SSH configuration"
    sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config 2>/dev/null
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config 2>/dev/null
    systemctl restart ssh sshd 2>/dev/null
    
    log_action "Rapid remediation completed"
}

fix_common_vulnerabilities
