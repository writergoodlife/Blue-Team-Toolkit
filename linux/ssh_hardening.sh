#!/bin/bash

# ============================================================================
# SSH Hardening Automation for CEG25 Competition
# ============================================================================
# Comprehensive SSH security hardening for energy infrastructure
# Optimized for CEG25 competition scoring and Blue Team defense
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="SSH Hardening Automation"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
LOG_DIR="../logs/ssh_hardening"
REPORT_DIR="../reports/ssh_hardening"
CONFIG_DIR="../config/ssh_hardening"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# SSH hardening configuration
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_BACKUP="/etc/ssh/sshd_config.backup.${TIMESTAMP}"
SSHD_SERVICE="sshd"

# SSH security settings for CEG25
declare -A SSH_SECURITY_SETTINGS=(
    ["PermitRootLogin"]="no"
    ["PasswordAuthentication"]="no"
    ["PermitEmptyPasswords"]="no"
    ["ChallengeResponseAuthentication"]="no"
    ["UsePAM"]="yes"
    ["X11Forwarding"]="no"
    ["AllowTcpForwarding"]="no"
    ["AllowAgentForwarding"]="no"
    ["PermitTunnel"]="no"
    ["MaxAuthTries"]="3"
    ["MaxSessions"]="2"
    ["LoginGraceTime"]="30"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="2"
    ["IgnoreRhosts"]="yes"
    ["HostbasedAuthentication"]="no"
    ["PermitUserEnvironment"]="no"
    ["StrictModes"]="yes"
    ["Compression"]="delayed"
    ["TCPKeepAlive"]="no"
    ["PrintMotd"]="no"
    ["PrintLastLog"]="no"
    ["UseDNS"]="no"
    ["GSSAPIAuthentication"]="no"
    ["GSSAPICleanupCredentials"]="no"
    ["KerberosAuthentication"]="no"
    ["KerberosOrLocalPasswd"]="no"
    ["KerberosTicketCleanup"]="no"
)

# SSH ciphers and algorithms (secure defaults)
SSH_CIPHERS="aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
SSH_MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
SSH_KEX_ALGORITHMS="curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"

# SSH allowed users/groups for energy infrastructure
SSH_ALLOWED_USERS="admin,operator,engineer"
SSH_ALLOWED_GROUPS="wheel,sudo,energy_ops"

# Create necessary directories
create_directories() {
    local dirs=("$LOG_DIR" "$REPORT_DIR" "$CONFIG_DIR")
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir" 2>/dev/null
    done
}

# Logging function
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        "INFO")     echo -e "${GREEN}[INFO]${NC}  $message" ;;
        "WARN")     echo -e "${YELLOW}[WARN]${NC}  $message" ;;
        "ERROR")    echo -e "${RED}[ERROR]${NC} $message" ;;
        "SUCCESS")  echo -e "${BOLD}${GREEN}[SUCCESS]${NC} $message" ;;
        "CRITICAL") echo -e "${WHITE}${RED}[CRITICAL]${NC} $message" ;;
    esac

    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/ssh_hardening_${TIMESTAMP}.log"
}

# Display SSH hardening banner
show_banner() {
    clear
    echo -e "${BOLD}${BLUE}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo "    🔐 SSH Hardening Automation for CEG25 Competition 🔐"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo -e "${WHITE}Version: $VERSION | Energy Infrastructure SSH Security${NC}"
    echo -e "${WHITE}Target: SSH Service Hardening | Competition Scoring Optimized${NC}"
    echo -e "${WHITE}Date: October 28-30, 2025 | Location: Warsaw, Poland${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${BOLD}${YELLOW}🔒 SSH SECURITY MISSION: Harden SSH for Energy Infrastructure${NC}"
    echo -e "${WHITE}• Disable root login and password authentication${NC}"
    echo -e "${WHITE}• Implement key-based authentication only${NC}"
    echo -e "${WHITE}• Configure secure ciphers and algorithms${NC}"
    echo -e "${WHITE}• Enable rate limiting and intrusion detection${NC}"
    echo
}

# Backup current SSH configuration
backup_ssh_config() {
    log_message "INFO" "Creating backup of current SSH configuration"

    if [[ -f "$SSH_CONFIG" ]]; then
        cp "$SSH_CONFIG" "$SSH_CONFIG_BACKUP"
        log_message "SUCCESS" "SSH configuration backed up to: $(basename "$SSH_CONFIG_BACKUP")"
    else
        log_message "ERROR" "SSH configuration file not found: $SSH_CONFIG"
        return 1
    fi
}

# Check current SSH configuration
check_ssh_config() {
    log_message "INFO" "Analyzing current SSH configuration"

    echo -e "${BOLD}${CYAN}🔍 SSH CONFIGURATION ANALYSIS${NC}"
    echo

    # Check if SSH service is running
    if systemctl is-active --quiet "$SSHD_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ SSH service is running${NC}"
    else
        echo -e "${YELLOW}⚠ SSH service is not running${NC}"
    fi

    # Check current SSH version
    local ssh_version=$(ssh -V 2>&1 | head -1)
    echo -e "${WHITE}SSH Version: ${CYAN}$ssh_version${NC}"

    # Check current configuration settings
    echo
    echo -e "${BOLD}${WHITE}Current SSH Security Settings:${NC}"
    for setting in "${!SSH_SECURITY_SETTINGS[@]}"; do
        local current_value=$(grep "^$setting" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}')
        local recommended="${SSH_SECURITY_SETTINGS[$setting]}"

        if [[ -z "$current_value" ]]; then
            echo -e "${YELLOW}⚠ $setting: NOT SET (recommended: $recommended)${NC}"
        elif [[ "$current_value" == "$recommended" ]]; then
            echo -e "${GREEN}✓ $setting: $current_value${NC}"
        else
            echo -e "${RED}✗ $setting: $current_value (recommended: $recommended)${NC}"
        fi
    done
}

# Apply SSH hardening configuration
apply_ssh_hardening() {
    log_message "INFO" "Applying SSH hardening configuration"

    echo -e "${BOLD}${RED}🔒 APPLYING SSH HARDENING${NC}"
    echo -e "${WHITE}Configuring secure SSH settings for energy infrastructure...${NC}"
    echo

    # Create new SSH configuration
    local temp_config="/tmp/sshd_config_hardened"

    # Start with current config
    cp "$SSH_CONFIG" "$temp_config"

    # Apply security settings
    for setting in "${!SSH_SECURITY_SETTINGS[@]}"; do
        local value="${SSH_SECURITY_SETTINGS[$setting]}"

        # Remove existing setting
        sed -i "/^$setting/d" "$temp_config"

        # Add new setting
        echo "$setting $value" >> "$temp_config"

        log_message "INFO" "Set $setting = $value"
    done

    # Add cipher and algorithm restrictions
    echo "" >> "$temp_config"
    echo "# Secure ciphers and algorithms for CEG25" >> "$temp_config"
    echo "Ciphers $SSH_CIPHERS" >> "$temp_config"
    echo "MACs $SSH_MACS" >> "$temp_config"
    echo "KexAlgorithms $SSH_KEX_ALGORITHMS" >> "$temp_config"

    # Add allowed users/groups for energy infrastructure
    echo "" >> "$temp_config"
    echo "# Energy infrastructure access control" >> "$temp_config"
    echo "AllowUsers $SSH_ALLOWED_USERS" >> "$temp_config"
    echo "AllowGroups $SSH_ALLOWED_GROUPS" >> "$temp_config"

    # Replace original configuration
    mv "$temp_config" "$SSH_CONFIG"
    chmod 600 "$SSH_CONFIG"

    log_message "SUCCESS" "SSH hardening configuration applied"
}

# Configure SSH key-based authentication
configure_ssh_keys() {
    log_message "INFO" "Configuring SSH key-based authentication"

    echo -e "${BOLD}${PURPLE}🔑 SSH KEY CONFIGURATION${NC}"

    # Create .ssh directory for root if it doesn't exist
    if [[ ! -d "/root/.ssh" ]]; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        log_message "INFO" "Created /root/.ssh directory"
    fi

    # Generate SSH key pair if none exists
    if [[ ! -f "/root/.ssh/id_rsa" ]]; then
        echo -e "${WHITE}Generating SSH key pair for root...${NC}"
        ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" -C "CEG25-Energy-Infrastructure-$(hostname)" >/dev/null 2>&1

        # Add public key to authorized_keys
        cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys

        log_message "SUCCESS" "SSH key pair generated and configured"
        echo -e "${GREEN}✓ SSH key pair generated${NC}"
        echo -e "${WHITE}Private key: ${CYAN}/root/.ssh/id_rsa${NC}"
        echo -e "${WHITE}Public key: ${CYAN}/root/.ssh/id_rsa.pub${NC}"
    else
        echo -e "${GREEN}✓ SSH key pair already exists${NC}"
    fi

    # Configure SSH agent for automated key management
    if [[ ! -f "/etc/systemd/system/ssh-agent.service" ]]; then
        cat > "/etc/systemd/system/ssh-agent.service" << EOF
[Unit]
Description=SSH Agent
After=network.target

[Service]
Type=simple
Environment=SSH_AUTH_SOCK=%t/ssh-agent.socket
ExecStart=/usr/bin/ssh-agent -D -a \$SSH_AUTH_SOCK
ExecStop=/usr/bin/ssh-agent -k

[Install]
WantedBy=default.target
EOF
        systemctl daemon-reload
        systemctl enable ssh-agent
        log_message "SUCCESS" "SSH agent service configured"
    fi
}

# Configure fail2ban for SSH protection
configure_fail2ban() {
    log_message "INFO" "Configuring fail2ban for SSH intrusion detection"

    echo -e "${BOLD}${YELLOW}🛡️ FAIL2BAN CONFIGURATION${NC}"

    # Check if fail2ban is installed
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "${WHITE}Installing fail2ban...${NC}"
        apt-get update >/dev/null 2>&1 && apt-get install -y fail2ban >/dev/null 2>&1 || \
        yum install -y fail2ban >/dev/null 2>&1 || \
        dnf install -y fail2ban >/dev/null 2>&1

        if [[ $? -eq 0 ]]; then
            log_message "SUCCESS" "fail2ban installed"
        else
            log_message "WARN" "Failed to install fail2ban"
            return 1
        fi
    fi

    # Configure fail2ban for SSH
    local fail2ban_ssh_config="/etc/fail2ban/jail.d/ssh-ceg25.conf"

    cat > "$fail2ban_ssh_config" << EOF
[sshd-ceg25]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
ignoreip = 127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
EOF

    # Start fail2ban service
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl start fail2ban >/dev/null 2>&1

    if systemctl is-active --quiet fail2ban; then
        log_message "SUCCESS" "fail2ban configured and started for SSH protection"
        echo -e "${GREEN}✓ fail2ban active - SSH intrusion detection enabled${NC}"
    else
        log_message "WARN" "Failed to start fail2ban service"
    fi
}

# Configure SSH rate limiting with iptables
configure_rate_limiting() {
    log_message "INFO" "Configuring SSH rate limiting"

    echo -e "${BOLD}${BLUE}⏱️ SSH RATE LIMITING${NC}"

    # Check if iptables is available
    if command -v iptables >/dev/null 2>&1; then
        # Create SSH rate limiting chain
        iptables -N SSH_RATE_LIMIT 2>/dev/null || iptables -F SSH_RATE_LIMIT

        # Allow 3 connections per minute from same IP
        iptables -A SSH_RATE_LIMIT -m recent --set --name SSH --rsource
        iptables -A SSH_RATE_LIMIT -m recent ! --rcheck --seconds 60 --hitcount 3 --name SSH --rsource -j RETURN
        iptables -A SSH_RATE_LIMIT -j LOG --log-prefix "SSH_RATE_LIMIT_DROP: "
        iptables -A SSH_RATE_LIMIT -j DROP

        # Apply rate limiting to SSH port
        iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j SSH_RATE_LIMIT

        # Save iptables rules
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null

        log_message "SUCCESS" "SSH rate limiting configured (3 connections/minute)"
        echo -e "${GREEN}✓ SSH rate limiting active${NC}"
    else
        log_message "WARN" "iptables not available for rate limiting"
    fi
}

# Test SSH configuration
test_ssh_config() {
    log_message "INFO" "Testing SSH configuration"

    echo -e "${BOLD}${GREEN}🧪 SSH CONFIGURATION TEST${NC}"

    # Test SSH configuration syntax
    if sshd -t >/dev/null 2>&1; then
        echo -e "${GREEN}✓ SSH configuration syntax is valid${NC}"
        log_message "SUCCESS" "SSH configuration syntax test passed"
    else
        echo -e "${RED}✗ SSH configuration syntax error${NC}"
        log_message "ERROR" "SSH configuration syntax test failed"
        return 1
    fi

    # Test SSH service restart
    echo -e "${WHITE}Testing SSH service restart...${NC}"
    if systemctl restart "$SSHD_SERVICE" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ SSH service restarted successfully${NC}"
        log_message "SUCCESS" "SSH service restart test passed"
    else
        echo -e "${RED}✗ SSH service restart failed${NC}"
        log_message "ERROR" "SSH service restart test failed"
        return 1
    fi
}

# Generate SSH hardening report
generate_ssh_report() {
    local report_file="$REPORT_DIR/ssh_hardening_report_${TIMESTAMP}.txt"

    log_message "INFO" "Generating SSH hardening report"

    cat > "$report_file" << EOF
SSH Hardening Report - CEG25 Competition
Generated: $(date)
========================================

COMPETITION CONTEXT:
- Event: CyberEXPERT Game 2025 (CEG25)
- Phase: Energy Infrastructure Defense
- Location: Warsaw, Poland
- Date: October 28-30, 2025

SSH SECURITY ASSESSMENT:
EOF

    # SSH version and status
    echo "SSH Service Status:" >> "$report_file"
    echo "  Service: $(systemctl is-active "$SSHD_SERVICE" 2>/dev/null || echo 'Not managed by systemd')" >> "$report_file"
    echo "  Version: $(ssh -V 2>&1 | head -1)" >> "$report_file"
    echo "  Port: $(grep "^Port" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo '22 (default)')" >> "$report_file"
    echo "" >> "$report_file"

    # Security settings verification
    echo "Security Settings Applied:" >> "$report_file"
    for setting in "${!SSH_SECURITY_SETTINGS[@]}"; do
        local current_value=$(grep "^$setting" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}')
        local recommended="${SSH_SECURITY_SETTINGS[$setting]}"

        if [[ "$current_value" == "$recommended" ]]; then
            echo "  ✓ $setting = $current_value" >> "$report_file"
        else
            echo "  ✗ $setting = $current_value (should be: $recommended)" >> "$report_file"
        fi
    done
    echo "" >> "$report_file"

    # Additional security features
    echo "Additional Security Features:" >> "$report_file"
    echo "  Key-based Authentication: $([[ -f "/root/.ssh/id_rsa" ]] && echo '✓ Configured' || echo '✗ Not configured')" >> "$report_file"
    echo "  fail2ban Protection: $(systemctl is-active fail2ban 2>/dev/null >/dev/null && echo '✓ Active' || echo '✗ Inactive')" >> "$report_file"
    echo "  Rate Limiting: $(iptables -L | grep -q SSH_RATE_LIMIT && echo '✓ Active' || echo '✗ Inactive')" >> "$report_file"
    echo "" >> "$report_file"

    # CEG25 compliance
    echo "CEG25 Competition Compliance:" >> "$report_file"
    echo "  Root Login Disabled: $(grep -q "^PermitRootLogin no" "$SSH_CONFIG" && echo '✓ Compliant' || echo '✗ Non-compliant')" >> "$report_file"
    echo "  Password Auth Disabled: $(grep -q "^PasswordAuthentication no" "$SSH_CONFIG" && echo '✓ Compliant' || echo '✗ Non-compliant')" >> "$report_file"
    echo "  Secure Ciphers: $(grep -q "^Ciphers" "$SSH_CONFIG" && echo '✓ Configured' || echo '✗ Not configured')" >> "$report_file"
    echo "  Access Control: $(grep -q "^AllowUsers\|^AllowGroups" "$SSH_CONFIG" && echo '✓ Configured' || echo '✗ Not configured')" >> "$report_file"
    echo "" >> "$report_file"

    # Recommendations
    echo "Recommendations for Competition:" >> "$report_file"
    echo "1. Distribute SSH public keys to authorized administrators" >> "$report_file"
    echo "2. Monitor SSH logs for unauthorized access attempts" >> "$report_file"
    echo "3. Regularly rotate SSH keys and update configurations" >> "$report_file"
    echo "4. Test SSH access before competition phases" >> "$report_file"
    echo "5. Document authorized SSH access for incident response" >> "$report_file"
    echo "" >> "$report_file"

    echo "Backup Location: $(basename "$SSH_CONFIG_BACKUP")" >> "$report_file"

    log_message "SUCCESS" "SSH hardening report generated: $(basename "$report_file")"
    echo -e "${GREEN}📄 SSH Hardening Report: ${WHITE}$report_file${NC}"
}

# Main SSH hardening workflow
main() {
    show_banner
    create_directories

    case "${1:-harden}" in
        "analyze"|"check")
            check_ssh_config
            ;;
        "harden"|"secure")
            echo -e "${BOLD}${YELLOW}🚀 STARTING SSH HARDENING FOR CEG25 COMPETITION${NC}"
            echo

            backup_ssh_config
            check_ssh_config
            apply_ssh_hardening
            configure_ssh_keys
            configure_fail2ban
            configure_rate_limiting
            test_ssh_config
            generate_ssh_report

            echo
            echo -e "${BOLD}${GREEN}✅ SSH HARDENING COMPLETED${NC}"
            echo -e "${WHITE}SSH service is now hardened for energy infrastructure defense${NC}"
            log_message "CEG25" "SSH hardening completed for CEG25 competition"
            ;;
        "backup")
            backup_ssh_config
            ;;
        "test")
            test_ssh_config
            ;;
        "report")
            generate_ssh_report
            ;;
        "help"|*)
            echo -e "${BOLD}${CYAN}SSH Hardening Automation Commands:${NC}"
            echo
            echo -e "${WHITE}Security Operations:${NC}"
            echo -e "  ${YELLOW}analyze${NC}    - Analyze current SSH configuration"
            echo -e "  ${YELLOW}harden${NC}     - Apply complete SSH hardening (default)"
            echo -e "  ${YELLOW}backup${NC}     - Create SSH configuration backup"
            echo -e "  ${YELLOW}test${NC}       - Test SSH configuration and service"
            echo -e "  ${YELLOW}report${NC}     - Generate SSH hardening report"
            echo -e "  ${YELLOW}help${NC}       - Show this help message"
            echo
            echo -e "${BOLD}${YELLOW}CEG25 Competition Features:${NC}"
            echo -e "  ${WHITE}• Energy infrastructure access control${NC}"
            echo -e "  ${WHITE}• Competition-optimized security settings${NC}"
            echo -e "  ${WHITE}• fail2ban intrusion detection${NC}"
            echo -e "  ${WHITE}• SSH rate limiting protection${NC}"
            echo -e "  ${WHITE}• Key-based authentication enforcement${NC}"
            echo
            echo -e "${BOLD}${RED}⚠️  WARNING: SSH hardening disables password authentication${NC}"
            echo -e "${WHITE}Ensure SSH keys are distributed before running in production${NC}"
            ;;
    esac
}

# Execute main function with all arguments
main "$@"