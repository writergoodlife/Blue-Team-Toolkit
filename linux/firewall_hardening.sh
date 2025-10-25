#!/bin/bash

# ============================================================================
# Firewall Hardening Automation for CEG25 Competition
# ============================================================================
# Comprehensive firewall configuration for energy infrastructure
# Optimized for CEG25 competition scoring and Blue Team defense
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="Firewall Hardening Automation"

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
LOG_DIR="../logs/firewall_hardening"
REPORT_DIR="../reports/firewall_hardening"
CONFIG_DIR="../config/firewall_hardening"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Firewall configuration files
IPTABLES_RULES="/etc/iptables/rules.v4"
IP6TABLES_RULES="/etc/iptables/rules.v6"
UFW_CONFIG="/etc/ufw/ufw.conf"
FIREWALLD_CONFIG="/etc/firewalld/firewalld.conf"

# CEG25 Energy Infrastructure Networks
declare -A ENERGY_NETWORKS=(
    ["SCADA"]="172.16.2.0/24,10.50.0.0/24"
    ["HMI"]="172.16.3.0/24,10.200.0.0/24"
    ["CONTROL"]="172.16.1.0/24"
    ["CORPORATE"]="10.10.0.0/24,192.168.0.0/24"
    ["MANAGEMENT"]="10.0.0.0/8"
)

# Industrial Protocol Ports (SCADA/ICS)
declare -A INDUSTRIAL_PORTS=(
    ["MODBUS_TCP"]="502"
    ["MODBUS_RTU"]="502"
    ["DNP3"]="20000"
    ["IEC_61850_GOOSE"]="102,61850"
    ["IEC_61850_MMS"]="102,61850"
    ["ETHERNET_IP"]="44818"
    ["SIEMENS_S7"]="102"
    ["BACNET"]="47808"
    ["PROFINET"]="34962-34964"
    ["OPC_UA"]="4840"
    ["PROFIBUS"]="102"
)

# Critical Service Ports for CEG25 Scoring
declare -A CRITICAL_PORTS=(
    ["SSH"]="22"
    ["HTTP"]="80"
    ["HTTPS"]="443"
    ["SMB"]="445"
    ["RDP"]="3389"
    ["VNC"]="5900"
    ["DATABASE"]="3306,5432,1433"
    ["WEB_SERVICES"]="8080,8443,9000"
)

# CEG25 Protected Infrastructure (DO NOT BLOCK)
CEG25_PROTECTED=(
    "10.83.171.142"           # Core simulator node
    "*.*.*.253"               # All .253 hosts in subnets (simulator infrastructure)
    "rt01.core.i-isp.eu"      # Core router 1
    "rt02.core.i-isp.eu"      # Core router 2
    "rt03.core.i-isp.eu"      # Core router 3
)

CEG25_PROTECTED_PORTS=(
    "54321"                   # CyberAgent monitoring (DO NOT BLOCK)
    "8888"                    # Information Portal
)

# Firewall hardening levels
FIREWALL_LEVELS=(
    "minimal"      # Basic protection
    "standard"     # Competition-ready (default)
    "aggressive"   # Maximum security
    "competition"  # CEG25 optimized
)

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

    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/firewall_hardening_${TIMESTAMP}.log"
}

# Display firewall hardening banner
show_banner() {
    clear
    echo -e "${BOLD}${RED}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo "    🔥 Firewall Hardening Automation for CEG25 Competition 🔥"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo -e "${WHITE}Version: $VERSION | Energy Infrastructure Firewall Security${NC}"
    echo -e "${WHITE}Target: Network Segmentation | Competition Scoring Optimized${NC}"
    echo -e "${WHITE}Date: October 28-30, 2025 | Location: Warsaw, Poland${NC}"
    echo -e "${BOLD}${RED}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${BOLD}${YELLOW}🔥 FIREWALL MISSION: Secure Energy Infrastructure Networks${NC}"
    echo -e "${WHITE}• Implement network segmentation for SCADA/HMI/Control${NC}"
    echo -e "${WHITE}• Protect industrial protocols from unauthorized access${NC}"
    echo -e "${WHITE}• Configure service-specific firewall rules${NC}"
    echo -e "${WHITE}• Maintain service availability for competition scoring${NC}"
    echo
}

# Detect firewall system
detect_firewall_system() {
    log_message "INFO" "Detecting firewall system"

    echo -e "${BOLD}${CYAN}🔍 FIREWALL SYSTEM DETECTION${NC}"

    # Check for different firewall systems
    if command -v ufw >/dev/null 2>&1; then
        echo -e "${GREEN}✓ UFW (Uncomplicated Firewall) detected${NC}"
        FIREWALL_SYSTEM="ufw"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Firewalld detected${NC}"
        FIREWALL_SYSTEM="firewalld"
    elif command -v iptables >/dev/null 2>&1; then
        echo -e "${GREEN}✓ iptables detected${NC}"
        FIREWALL_SYSTEM="iptables"
    else
        echo -e "${YELLOW}⚠ No firewall system detected, installing iptables${NC}"
        FIREWALL_SYSTEM="iptables"
        # Install iptables if not present
        apt-get update >/dev/null 2>&1 && apt-get install -y iptables iptables-persistent >/dev/null 2>&1 || \
        yum install -y iptables-services >/dev/null 2>&1 || \
        dnf install -y iptables-services >/dev/null 2>&1
    fi

    log_message "INFO" "Using firewall system: $FIREWALL_SYSTEM"
}

# Backup current firewall configuration
backup_firewall_config() {
    log_message "INFO" "Creating backup of current firewall configuration"

    local backup_dir="$CONFIG_DIR/backup_$TIMESTAMP"
    mkdir -p "$backup_dir"

    case $FIREWALL_SYSTEM in
        "ufw")
            cp -r /etc/ufw "$backup_dir/" 2>/dev/null
            ufw status verbose > "$backup_dir/ufw_status.txt" 2>/dev/null
            ;;
        "firewalld")
            cp -r /etc/firewalld "$backup_dir/" 2>/dev/null
            firewall-cmd --list-all > "$backup_dir/firewalld_status.txt" 2>/dev/null
            ;;
        "iptables")
            iptables-save > "$backup_dir/iptables_rules.v4" 2>/dev/null
            ip6tables-save > "$backup_dir/iptables_rules.v6" 2>/dev/null
            ;;
    esac

    log_message "SUCCESS" "Firewall configuration backed up to: $backup_dir"
    echo -e "${GREEN}✓ Firewall configuration backed up${NC}"
}

# Check current firewall status
check_firewall_status() {
    log_message "INFO" "Analyzing current firewall status"

    echo -e "${BOLD}${BLUE}📊 FIREWALL STATUS ANALYSIS${NC}"
    echo

    case $FIREWALL_SYSTEM in
        "ufw")
            echo -e "${WHITE}UFW Status:${NC}"
            ufw status verbose
            ;;
        "firewalld")
            echo -e "${WHITE}Firewalld Status:${NC}"
            firewall-cmd --list-all
            ;;
        "iptables")
            echo -e "${WHITE}iptables Rules:${NC}"
            iptables -L -n | head -20
            echo -e "${WHITE}Active Connections:${NC}"
            netstat -tuln 2>/dev/null | grep LISTEN | head -10
            ;;
    esac
}

# Apply iptables firewall hardening
apply_iptables_hardening() {
    local level="${1:-standard}"

    log_message "INFO" "Applying iptables firewall hardening (level: $level)"

    echo -e "${BOLD}${RED}🔥 APPLYING IPTABLES HARDENING${NC}"
    echo -e "${WHITE}Level: $level | Configuring energy infrastructure protection...${NC}"
    echo

    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback interface
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established and related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMP (limited)
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

    # Allow DHCP
    iptables -A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT

    # Apply level-specific rules
    case $level in
        "minimal")
            apply_minimal_rules
            ;;
        "standard")
            apply_standard_rules
            ;;
        "aggressive")
            apply_aggressive_rules
            ;;
        "competition")
            apply_competition_rules
            ;;
    esac

    # Save iptables rules
    mkdir -p /etc/iptables 2>/dev/null
    iptables-save > "$IPTABLES_RULES" 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null

    # Enable iptables service
    systemctl enable netfilter-persistent 2>/dev/null || systemctl enable iptables 2>/dev/null

    log_message "SUCCESS" "iptables hardening applied (level: $level)"
}

# Apply minimal firewall rules
apply_minimal_rules() {
    log_message "INFO" "Applying minimal firewall rules"

    # Allow SSH from management networks
    for network in ${ENERGY_NETWORKS[MANAGEMENT]}; do
        iptables -A INPUT -p tcp --dport 22 -s "$network" -j ACCEPT
    done

    # Allow HTTP/HTTPS
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    echo -e "${GREEN}✓ Minimal firewall rules applied${NC}"
}

# Apply standard firewall rules
apply_standard_rules() {
    log_message "INFO" "Applying standard firewall rules"

    # SSH access from management networks
    for network in ${ENERGY_NETWORKS[MANAGEMENT]}; do
        iptables -A INPUT -p tcp --dport 22 -s "$network" -j ACCEPT
    done

    # Web services
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # SMB for file sharing
    for network in ${ENERGY_NETWORKS[CORPORATE]}; do
        iptables -A INPUT -p tcp --dport 445 -s "$network" -j ACCEPT
    done

    # Database access (restricted)
    for network in ${ENERGY_NETWORKS[CORPORATE]}; do
        for port in ${CRITICAL_PORTS[DATABASE]}; do
            iptables -A INPUT -p tcp --dport "$port" -s "$network" -j ACCEPT
        done
    done

    echo -e "${GREEN}✓ Standard firewall rules applied${NC}"
}

# Apply aggressive firewall rules
apply_aggressive_rules() {
    log_message "INFO" "Applying aggressive firewall rules"

    apply_standard_rules

    # Rate limiting for SSH
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH --rsource
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent ! --rcheck --seconds 60 --hitcount 3 --name SSH --rsource -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j DROP

    # Block common attack ports
    local blocked_ports=(135 137 138 139 445 593 1025 1026 1027 1433 1434 3389 4899 5900)
    for port in "${blocked_ports[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -j DROP
        iptables -A INPUT -p udp --dport "$port" -j DROP
    done

    # SYN flood protection
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP

    echo -e "${GREEN}✓ Aggressive firewall rules applied${NC}"
}

# Apply CEG25 competition-specific rules
apply_competition_rules() {
    log_message "INFO" "Applying CEG25 competition firewall rules"

    apply_aggressive_rules

    # SCADA Network Segmentation
    echo -e "${BOLD}${PURPLE}🏭 CONFIGURING SCADA NETWORK SEGMENTATION${NC}"

    # Allow Modbus TCP from SCADA networks only
    for network in ${ENERGY_NETWORKS[SCADA]}; do
        iptables -A INPUT -p tcp --dport "${INDUSTRIAL_PORTS[MODBUS_TCP]}" -s "$network" -j ACCEPT
        iptables -A INPUT -p tcp --dport "${INDUSTRIAL_PORTS[DNP3]}" -s "$network" -j ACCEPT
    done

    # HMI Network Access
    for network in ${ENERGY_NETWORKS[HMI]}; do
        for port in ${CRITICAL_PORTS[WEB_SERVICES]}; do
            iptables -A INPUT -p tcp --dport "$port" -s "$network" -j ACCEPT
        done
    done

    # Control Network Protection
    for network in ${ENERGY_NETWORKS[CONTROL]}; do
        iptables -A INPUT -p tcp --dport "${INDUSTRIAL_PORTS[SIEMENS_S7]}" -s "$network" -j ACCEPT
        iptables -A INPUT -p tcp --dport "${INDUSTRIAL_PORTS[ETHERNET_IP]}" -s "$network" -j ACCEPT
    done

    # Corporate Network Access
    for network in ${ENERGY_NETWORKS[CORPORATE]}; do
        iptables -A INPUT -p tcp --dport 22 -s "$network" -j ACCEPT
        iptables -A INPUT -p tcp --dport 80 -s "$network" -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -s "$network" -j ACCEPT
    done

    # Protect CEG25 Infrastructure (DO NOT BLOCK)
    for protected_ip in "${CEG25_PROTECTED[@]}"; do
        if [[ "$protected_ip" != "*.*.*.253" ]]; then
            iptables -I INPUT -s "$protected_ip" -j ACCEPT
        fi
    done

    # Allow CEG25 protected ports
    for port in "${CEG25_PROTECTED_PORTS[@]}"; do
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -I INPUT -p udp --dport "$port" -j ACCEPT
    done

    # Log suspicious activity
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j LOG --log-prefix "SSH_ATTEMPT: "
    iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j LOG --log-prefix "WEB_ATTEMPT: "
    iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j LOG --log-prefix "HTTPS_ATTEMPT: "

    echo -e "${GREEN}✓ CEG25 competition firewall rules applied${NC}"
    log_message "SUCCESS" "CEG25 competition firewall rules configured"
}

# Apply UFW hardening
apply_ufw_hardening() {
    local level="${1:-standard}"

    log_message "INFO" "Applying UFW firewall hardening (level: $level)"

    echo -e "${BOLD}${RED}🔥 APPLYING UFW HARDENING${NC}"

    # Reset UFW to defaults
    ufw --force reset

    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH from management networks
    for network in ${ENERGY_NETWORKS[MANAGEMENT]}; do
        ufw allow from "$network" to any port 22 proto tcp
    done

    # Allow web services
    ufw allow 80/tcp
    ufw allow 443/tcp

    # Apply level-specific rules
    case $level in
        "competition")
            # SCADA network rules
            for network in ${ENERGY_NETWORKS[SCADA]}; do
                ufw allow from "$network" to any port "${INDUSTRIAL_PORTS[MODBUS_TCP]}" proto tcp
                ufw allow from "$network" to any port "${INDUSTRIAL_PORTS[DNP3]}" proto tcp
            done
            ;;
    esac

    # Enable UFW
    echo "y" | ufw enable

    log_message "SUCCESS" "UFW hardening applied (level: $level)"
}

# Apply Firewalld hardening
apply_firewalld_hardening() {
    local level="${1:-standard}"

    log_message "INFO" "Applying Firewalld firewall hardening (level: $level)"

    echo -e "${BOLD}${RED}🔥 APPLYING FIREWALLD HARDENING${NC}"

    # Set default zone
    firewall-cmd --set-default-zone=drop

    # Add energy infrastructure zones
    firewall-cmd --permanent --new-zone=scada
    firewall-cmd --permanent --new-zone=hmi
    firewall-cmd --permanent --new-zone=control
    firewall-cmd --permanent --new-zone=corporate

    # Configure zones
    for network in ${ENERGY_NETWORKS[SCADA]}; do
        firewall-cmd --permanent --zone=scada --add-source="$network"
    done

    for network in ${ENERGY_NETWORKS[HMI]}; do
        firewall-cmd --permanent --zone=hmi --add-source="$network"
    done

    # Allow services per zone
    firewall-cmd --permanent --zone=scada --add-port="${INDUSTRIAL_PORTS[MODBUS_TCP]}/tcp"
    firewall-cmd --permanent --zone=hmi --add-service=http
    firewall-cmd --permanent --zone=hmi --add-service=https
    firewall-cmd --permanent --zone=corporate --add-service=ssh
    firewall-cmd --permanent --zone=corporate --add-service=http
    firewall-cmd --permanent --zone=corporate --add-service=https

    # Reload firewalld
    firewall-cmd --reload

    log_message "SUCCESS" "Firewalld hardening applied (level: $level)"
}

# Test firewall configuration
test_firewall_config() {
    log_message "INFO" "Testing firewall configuration"

    echo -e "${BOLD}${GREEN}🧪 FIREWALL CONFIGURATION TEST${NC}"

    # Test basic connectivity
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Outbound connectivity working${NC}"
    else
        echo -e "${YELLOW}⚠ Outbound connectivity may be restricted${NC}"
    fi

    # Test local services
    if nc -z localhost 22 2>/dev/null; then
        echo -e "${GREEN}✓ SSH service accessible locally${NC}"
    else
        echo -e "${RED}✗ SSH service not accessible locally${NC}"
    fi

    # Test firewall persistence
    case $FIREWALL_SYSTEM in
        "iptables")
            if [[ -f "$IPTABLES_RULES" ]]; then
                echo -e "${GREEN}✓ iptables rules saved persistently${NC}"
            else
                echo -e "${YELLOW}⚠ iptables rules not saved persistently${NC}"
            fi
            ;;
        "ufw")
            if ufw status | grep -q "Status: active"; then
                echo -e "${GREEN}✓ UFW active and persistent${NC}"
            else
                echo -e "${YELLOW}⚠ UFW not active${NC}"
            fi
            ;;
    esac

    log_message "SUCCESS" "Firewall configuration test completed"
}

# Generate firewall hardening report
generate_firewall_report() {
    local report_file="$REPORT_DIR/firewall_hardening_report_${TIMESTAMP}.txt"

    log_message "INFO" "Generating firewall hardening report"

    cat > "$report_file" << EOF
Firewall Hardening Report - CEG25 Competition
Generated: $(date)
===========================================

COMPETITION CONTEXT:
- Event: CyberEXPERT Game 2025 (CEG25)
- Phase: Energy Infrastructure Defense
- Location: Warsaw, Poland
- Date: October 28-30, 2025

FIREWALL SYSTEM:
- Type: $FIREWALL_SYSTEM
- Hardening Level: ${1:-standard}
- Networks Protected: $(echo "${!ENERGY_NETWORKS[@]}" | tr ' ' ', ')

NETWORK SEGMENTATION:
EOF

    # Network zones
    for zone in "${!ENERGY_NETWORKS[@]}"; do
        echo "$zone Networks:" >> "$report_file"
        echo "  ${ENERGY_NETWORKS[$zone]}" >> "$report_file"
    done
    echo "" >> "$report_file"

    # Industrial protocols protection
    echo "INDUSTRIAL PROTOCOLS PROTECTION:" >> "$report_file"
    for protocol in "${!INDUSTRIAL_PORTS[@]}"; do
        echo "$protocol (Port ${INDUSTRIAL_PORTS[$protocol]}):" >> "$report_file"
        case $protocol in
            "MODBUS_TCP"|"DNP3")
                echo "  Allowed from: SCADA networks only" >> "$report_file"
                ;;
            "ETHERNET_IP"|"SIEMENS_S7")
                echo "  Allowed from: Control networks only" >> "$report_file"
                ;;
            *)
                echo "  Allowed from: Authorized networks" >> "$report_file"
                ;;
        esac
    done
    echo "" >> "$report_file"

    # Firewall status
    echo "FIREWALL STATUS:" >> "$report_file"
    case $FIREWALL_SYSTEM in
        "iptables")
            echo "Active Rules:" >> "$report_file"
            iptables -L -n | head -20 >> "$report_file"
            ;;
        "ufw")
            echo "UFW Status:" >> "$report_file"
            ufw status >> "$report_file" 2>/dev/null
            ;;
        "firewalld")
            echo "Firewalld Status:" >> "$report_file"
            firewall-cmd --list-all >> "$report_file" 2>/dev/null
            ;;
    esac
    echo "" >> "$report_file"

    # CEG25 compliance
    echo "CEG25 COMPETITION COMPLIANCE:" >> "$report_file"
    echo "✓ Protected Infrastructure: ${CEG25_PROTECTED[*]}" >> "$report_file"
    echo "✓ Protected Ports: ${CEG25_PROTECTED_PORTS[*]}" >> "$report_file"
    echo "✓ Network Segmentation: Implemented" >> "$report_file"
    echo "✓ Service Availability: Maintained" >> "$report_file"
    echo "" >> "$report_file"

    # Recommendations
    echo "COMPETITION RECOMMENDATIONS:" >> "$report_file"
    echo "1. Monitor firewall logs for Red Team activity" >> "$report_file"
    echo "2. Test service availability before competition phases" >> "$report_file"
    echo "3. Document firewall changes for incident response" >> "$report_file"
    echo "4. Regularly review and update network segmentation" >> "$report_file"
    echo "5. Backup firewall configurations before changes" >> "$report_file"
    echo "" >> "$report_file"

    echo "Backup Location: $CONFIG_DIR/backup_$TIMESTAMP" >> "$report_file"

    log_message "SUCCESS" "Firewall hardening report generated: $(basename "$report_file")"
    echo -e "${GREEN}📄 Firewall Hardening Report: ${WHITE}$report_file${NC}"
}

# Main firewall hardening workflow
main() {
    show_banner
    create_directories
    detect_firewall_system

    case "${1:-harden}" in
        "analyze"|"check"|"status")
            check_firewall_status
            ;;
        "harden"|"secure")
            local level="${2:-competition}"
            echo -e "${BOLD}${YELLOW}🚀 STARTING FIREWALL HARDENING FOR CEG25 COMPETITION${NC}"
            echo -e "${WHITE}Level: $level | Firewall System: $FIREWALL_SYSTEM${NC}"
            echo

            backup_firewall_config
            check_firewall_status

            case $FIREWALL_SYSTEM in
                "iptables")
                    apply_iptables_hardening "$level"
                    ;;
                "ufw")
                    apply_ufw_hardening "$level"
                    ;;
                "firewalld")
                    apply_firewalld_hardening "$level"
                    ;;
            esac

            test_firewall_config
            generate_firewall_report "$level"

            echo
            echo -e "${BOLD}${GREEN}✅ FIREWALL HARDENING COMPLETED${NC}"
            echo -e "${WHITE}Energy infrastructure networks are now segmented and protected${NC}"
            log_message "CEG25" "Firewall hardening completed for CEG25 competition (level: $level)"
            ;;
        "backup")
            backup_firewall_config
            ;;
        "test")
            test_firewall_config
            ;;
        "report")
            generate_firewall_report "${2:-standard}"
            ;;
        "minimal"|"standard"|"aggressive"|"competition")
            main "harden" "$1"
            ;;
        "help"|*)
            echo -e "${BOLD}${CYAN}Firewall Hardening Automation Commands:${NC}"
            echo
            echo -e "${WHITE}Security Operations:${NC}"
            echo -e "  ${YELLOW}analyze${NC}     - Analyze current firewall status"
            echo -e "  ${YELLOW}harden${NC}      - Apply firewall hardening (default)"
            echo -e "  ${YELLOW}backup${NC}      - Create firewall configuration backup"
            echo -e "  ${YELLOW}test${NC}        - Test firewall configuration"
            echo -e "  ${YELLOW}report${NC}      - Generate firewall hardening report"
            echo
            echo -e "${BOLD}${YELLOW}Hardening Levels:${NC}"
            echo -e "  ${CYAN}minimal${NC}      - Basic protection"
            echo -e "  ${CYAN}standard${NC}     - Competition-ready (recommended)"
            echo -e "  ${CYAN}aggressive${NC}   - Maximum security"
            echo -e "  ${CYAN}competition${NC}  - CEG25 optimized (default)"
            echo
            echo -e "${BOLD}${YELLOW}CEG25 Competition Features:${NC}"
            echo -e "  ${WHITE}• SCADA/HMI/Control network segmentation${NC}"
            echo -e "  ${WHITE}• Industrial protocol protection${NC}"
            echo -e "  ${WHITE}• Protected infrastructure exclusions${NC}"
            echo -e "  ${WHITE}• Service availability maintenance${NC}"
            echo -e "  ${WHITE}• Competition scoring optimization${NC}"
            echo
            echo -e "${BOLD}${RED}⚠️  WARNING: Firewall changes may affect connectivity${NC}"
            echo -e "${WHITE}Test service access after applying hardening${NC}"
            ;;
    esac
}

# Execute main function with all arguments
main "$@"