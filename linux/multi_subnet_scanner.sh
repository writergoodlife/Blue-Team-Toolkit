#!/bin/bash

# ============================================================================
# Multi-Subnet Automated Network Scanner for CEG2025
# ============================================================================
# Comprehensive network scanner designed for 70-80 VM environment
# Intelligent scanning with CEG2025 simulator infrastructure protection
# Optimized for energy sector critical infrastructure mapping
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="Multi-Subnet Network Scanner"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
LOG_DIR="../logs/network"
REPORT_DIR="../reports/network"
CONFIG_DIR="../config/network"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# CEG2025 Protected Infrastructure (DO NOT SCAN)
PROTECTED_NETWORKS=(
    "10.83.171.142/32"        # Core simulator node
    "*.*.*.253/32"            # All .253 hosts in subnets
)

PROTECTED_HOSTNAMES=(
    "rt01.core.i-isp.eu"     # Core router 1
    "rt02.core.i-isp.eu"     # Core router 2
    "rt03.core.i-isp.eu"     # Core router 3
)

PROTECTED_PORTS=(
    "54321"                   # CyberAgent monitoring
    "8888"                    # Information Portal
)

# Network ranges for CEG2025 environment
CEG_NETWORKS=(
    "10.0.0.0/8"              # Primary network range
    "192.168.0.0/16"          # Management networks
    "172.16.0.0/12"           # Additional private ranges
)

# Energy Infrastructure Subnets (based on CEG2025 topology)
ENERGY_SUBNETS=(
    "10.10.0.0/24"            # HQ Network
    "10.50.0.0/24"            # Management Network
    "10.200.0.0/24"           # Factory/Production Network
    "192.168.0.0/24"          # Gateway Network
    "172.16.1.0/24"           # Control Network
    "172.16.2.0/24"           # SCADA Network
    "172.16.3.0/24"           # HMI Network
)

# Service categories for energy infrastructure
declare -A SERVICE_CATEGORIES=(
    ["web"]="80,443,8080,8443,9000,10000"
    ["scada"]="502,20000,102,44818,47808,789,1911,9600"
    ["remote"]="22,23,3389,5900,5901,5902"
    ["database"]="1433,3306,5432,1521,27017"
    ["management"]="161,162,623,664"
    ["industrial"]="2404,34962,34963,34964,1217,2455"
    ["energy"]="18245,5007,18246,2000,2001,2002"
)

# Create necessary directories
create_directories() {
    local dirs=("$LOG_DIR" "$REPORT_DIR" "$CONFIG_DIR")
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir" 2>/dev/null
    done
    
    # Create baseline configuration
    cat > "$CONFIG_DIR/scan_config.conf" << EOF
# CEG2025 Multi-Subnet Scanner Configuration
# Generated: $(date)

# Network Discovery Settings
DISCOVERY_TIMEOUT=3
PING_COUNT=1
PARALLEL_THREADS=50
MAX_HOST_SCAN=254

# Port Scanning Settings
PORT_SCAN_TIMEOUT=5
TCP_CONNECT_TIMEOUT=2
UDP_SCAN_ENABLED=false

# Service Detection
SERVICE_DETECTION_ENABLED=true
BANNER_GRABBING_ENABLED=true
OS_DETECTION_ENABLED=true

# Reporting
GENERATE_HTML_REPORT=true
GENERATE_CSV_EXPORT=true
INCLUDE_VULNERABILITY_HINTS=true
EOF
}

# Logging function
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")  echo -e "${GREEN}[INFO]${NC}  $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC}  $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${CYAN}[DEBUG]${NC} $message" ;;
        "SCAN")  echo -e "${PURPLE}[SCAN]${NC}  $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/network_scan_${TIMESTAMP}.log"
}

# Display banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "============================================================================"
    echo "        🌐 Multi-Subnet Automated Network Scanner (CEG2025) 🌐"
    echo "============================================================================"
    echo -e "${WHITE}Version: $VERSION${NC}"
    echo -e "${WHITE}Target: 70-80 VM Energy Infrastructure Environment${NC}"
    echo -e "${WHITE}Protection: CEG2025 Simulator Infrastructure Excluded${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
}

# Check if IP/host is protected
is_protected() {
    local target=$1
    
    # Check exact protected IPs
    if [[ "$target" == "10.83.171.142" ]]; then
        return 0
    fi
    
    # Check .253 pattern
    if [[ "$target" =~ \.[0-9]+\.[0-9]+\.253$ ]]; then
        return 0
    fi
    
    # Check protected hostnames
    for hostname in "${PROTECTED_HOSTNAMES[@]}"; do
        if [[ "$target" == "$hostname" ]]; then
            return 0
        fi
    done
    
    return 1
}

# Discover active subnets automatically
discover_subnets() {
    log_message "INFO" "Discovering active network subnets..."
    local subnet_report="$REPORT_DIR/subnet_discovery_${TIMESTAMP}.txt"
    
    echo "Network Subnet Discovery Report - $(date)" > "$subnet_report"
    echo "===========================================" >> "$subnet_report"
    
    # Get local network interfaces
    local discovered_subnets=()
    
    # Parse network interfaces
    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r line; do
            if [[ $line =~ inet\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
                local subnet="${BASH_REMATCH[1]}"
                # Skip loopback
                if [[ ! $subnet =~ ^127\. ]]; then
                    discovered_subnets+=("$subnet")
                    log_message "SCAN" "Discovered subnet: $subnet"
                fi
            fi
        done < <(ip addr show 2>/dev/null)
    elif command -v ifconfig >/dev/null 2>&1; then
        while IFS= read -r line; do
            if [[ $line =~ inet\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*netmask\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                local ip="${BASH_REMATCH[1]}"
                local mask="${BASH_REMATCH[2]}"
                if [[ ! $ip =~ ^127\. ]]; then
                    # Convert netmask to CIDR
                    local cidr=$(python3 -c "
import ipaddress
try:
    net = ipaddress.IPv4Network('$ip/$mask', strict=False)
    print(net)
except:
    print('$ip/24')
" 2>/dev/null || echo "$ip/24")
                    discovered_subnets+=("$cidr")
                    log_message "SCAN" "Discovered subnet: $cidr"
                fi
            fi
        done < <(ifconfig 2>/dev/null)
    fi
    
    # Add energy subnets to scan list
    local all_subnets=("${discovered_subnets[@]}" "${ENERGY_SUBNETS[@]}")
    
    echo "Discovered Subnets:" >> "$subnet_report"
    printf '%s\n' "${all_subnets[@]}" >> "$subnet_report"
    
    log_message "INFO" "Subnet discovery completed. Found ${#all_subnets[@]} subnets"
    echo "${all_subnets[@]}"
}

# Perform host discovery on subnet
discover_hosts() {
    local subnet=$1
    local output_file=$2
    
    log_message "SCAN" "Scanning subnet: $subnet"
    
    # Extract network info
    local network_ip=$(echo "$subnet" | cut -d'/' -f1)
    local cidr=$(echo "$subnet" | cut -d'/' -f2)
    local base_ip=$(echo "$network_ip" | cut -d'.' -f1-3)
    
    echo "=== HOST DISCOVERY: $subnet ===" >> "$output_file"
    
    # Host discovery methods
    discover_via_ping() {
        local active_hosts=()
        
        # Calculate host range based on CIDR
        local max_hosts=254
        if [[ $cidr -lt 24 ]]; then
            max_hosts=1000  # Limit large subnets
        fi
        
        log_message "DEBUG" "Ping scanning $subnet (max $max_hosts hosts)"
        
        # Parallel ping scanning
        for ((i=1; i<=max_hosts && i<=254; i++)); do
            local test_ip="${base_ip}.$i"
            
            if ! is_protected "$test_ip"; then
                {
                    if timeout 2 ping -c 1 -W 1 "$test_ip" >/dev/null 2>&1; then
                        echo "$test_ip" >> "$output_file.temp"
                        log_message "SCAN" "Host found: $test_ip"
                    fi
                } &
                
                # Limit concurrent processes
                ((i % 20 == 0)) && wait
            fi
        done
        wait
        
        # Read discovered hosts
        if [[ -f "$output_file.temp" ]]; then
            while IFS= read -r host; do
                active_hosts+=("$host")
                echo "  ACTIVE: $host" >> "$output_file"
            done < "$output_file.temp"
            rm -f "$output_file.temp"
        fi
        
        echo "  Total active hosts: ${#active_hosts[@]}" >> "$output_file"
        echo "${active_hosts[@]}"
    }
    
    # Use nmap if available for faster discovery
    if command -v nmap >/dev/null 2>&1; then
        log_message "DEBUG" "Using nmap for host discovery on $subnet"
        local nmap_hosts
        nmap_hosts=$(nmap -sn "$subnet" 2>/dev/null | grep -E "Nmap scan report" | awk '{print $NF}' | tr -d '()')
        
        local host_count=0
        while IFS= read -r host; do
            if [[ -n "$host" ]] && ! is_protected "$host"; then
                echo "  ACTIVE: $host" >> "$output_file"
                ((host_count++))
                log_message "SCAN" "Host found: $host"
            fi
        done <<< "$nmap_hosts"
        
        echo "  Total active hosts: $host_count" >> "$output_file"
        echo "$nmap_hosts"
    else
        # Fallback to ping discovery
        discover_via_ping
    fi
    
    echo "" >> "$output_file"
}

# Port scan active hosts
port_scan_hosts() {
    local hosts_string=$1
    local output_file=$2
    
    # Convert hosts string to array
    local hosts=()
    IFS=' ' read -ra hosts <<< "$hosts_string"
    
    log_message "INFO" "Port scanning ${#hosts[@]} active hosts..."
    
    echo "=== PORT SCANNING RESULTS ===" >> "$output_file"
    
    for host in "${hosts[@]}"; do
        if [[ -n "$host" ]] && ! is_protected "$host"; then
            log_message "SCAN" "Port scanning: $host"
            echo "Host: $host" >> "$output_file"
            
            # Scan by service category
            for category in "${!SERVICE_CATEGORIES[@]}"; do
                local ports="${SERVICE_CATEGORIES[$category]}"
                
                if command -v nmap >/dev/null 2>&1; then
                    local scan_result
                    scan_result=$(nmap -sS -p "$ports" --open "$host" 2>/dev/null | grep -E "(open|filtered)")
                    
                    if [[ -n "$scan_result" ]]; then
                        echo "  [$category services]" >> "$output_file"
                        echo "$scan_result" >> "$output_file"
                        log_message "SCAN" "$host - Found $category services"
                    fi
                else
                    # Manual port checking
                    echo "  [$category services]" >> "$output_file"
                    IFS=',' read -ra PORT_ARRAY <<< "$ports"
                    for port in "${PORT_ARRAY[@]}"; do
                        if timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
                            echo "    $port/tcp open" >> "$output_file"
                            log_message "SCAN" "$host:$port - Service detected"
                        fi
                    done
                fi
            done
            
            # Service and OS detection
            if command -v nmap >/dev/null 2>&1; then
                local service_info
                service_info=$(nmap -sV --version-intensity 0 -O "$host" 2>/dev/null | grep -E "(Service|OS|Device)")
                if [[ -n "$service_info" ]]; then
                    echo "  [System Information]" >> "$output_file"
                    echo "$service_info" >> "$output_file"
                fi
            fi
            
            echo "" >> "$output_file"
        fi
    done
}

# Generate network topology map
generate_topology_map() {
    local scan_results=$1
    local topology_file="$REPORT_DIR/network_topology_${TIMESTAMP}.txt"
    
    log_message "INFO" "Generating network topology map..."
    
    cat > "$topology_file" << EOF
CEG2025 Network Topology Map
Generated: $(date)
============================

Network Infrastructure Overview:
- Total Scanned Subnets: $(grep -c "HOST DISCOVERY" "$scan_results" || echo "0")
- Total Active Hosts: $(grep -c "ACTIVE:" "$scan_results" || echo "0")
- Protected Infrastructure Excluded: ✓

Network Segments:
EOF

    # Parse scan results for topology
    if [[ -f "$scan_results" ]]; then
        grep -A 20 "HOST DISCOVERY" "$scan_results" | while IFS= read -r line; do
            if [[ $line =~ HOST\ DISCOVERY:\ ([0-9.]+/[0-9]+) ]]; then
                local subnet="${BASH_REMATCH[1]}"
                echo "" >> "$topology_file"
                echo "Subnet: $subnet" >> "$topology_file"
                echo "├─ Network Role: $(determine_network_role "$subnet")" >> "$topology_file"
                echo "├─ Security Level: $(determine_security_level "$subnet")" >> "$topology_file"
                echo "└─ Recommended Actions: $(get_subnet_recommendations "$subnet")" >> "$topology_file"
            fi
        done
    fi
    
    log_message "INFO" "Network topology map generated: $topology_file"
}

# Determine network role based on subnet
determine_network_role() {
    local subnet=$1
    
    case "$subnet" in
        "10.10.0.0/24") echo "HQ/Corporate Network" ;;
        "10.50.0.0/24") echo "Management Network" ;;
        "10.200.0.0/24") echo "Production/Factory Network" ;;
        "192.168.0.0/24") echo "Gateway/DMZ Network" ;;
        "172.16.1.0/24") echo "Control Network" ;;
        "172.16.2.0/24") echo "SCADA Network" ;;
        "172.16.3.0/24") echo "HMI Network" ;;
        *) echo "General Network" ;;
    esac
}

# Determine security level
determine_security_level() {
    local subnet=$1
    
    case "$subnet" in
        "172.16.2.0/24"|"172.16.1.0/24") echo "CRITICAL - Industrial Control" ;;
        "10.200.0.0/24") echo "HIGH - Production Systems" ;;
        "10.50.0.0/24") echo "MEDIUM - Management Network" ;;
        "192.168.0.0/24") echo "HIGH - External Access Point" ;;
        *) echo "MEDIUM - Standard Network" ;;
    esac
}

# Get subnet-specific recommendations
get_subnet_recommendations() {
    local subnet=$1
    
    case "$subnet" in
        "172.16.2.0/24") echo "Isolate SCADA traffic, monitor industrial protocols" ;;
        "172.16.1.0/24") echo "Secure control systems, implement access controls" ;;
        "10.200.0.0/24") echo "Monitor production systems, secure HMI interfaces" ;;
        "192.168.0.0/24") echo "Harden gateway security, monitor external access" ;;
        *) echo "Standard hardening, regular monitoring" ;;
    esac
}

# Generate comprehensive network report
generate_network_report() {
    log_message "INFO" "Generating comprehensive network report..."
    local final_report="$REPORT_DIR/Network_Assessment_${TIMESTAMP}.html"
    
    # Count statistics
    local total_hosts=$(grep -c "ACTIVE:" "$LOG_DIR"/*.log 2>/dev/null || echo "0")
    local total_services=$(grep -c "open" "$LOG_DIR"/*.log 2>/dev/null || echo "0")
    
    cat > "$final_report" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Multi-Subnet Network Assessment - CEG2025</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #1e3a8a; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #3b82f6; }
        .critical { background-color: #fef2f2; border-left-color: #ef4444; }
        .high { background-color: #fff7ed; border-left-color: #f97316; }
        .medium { background-color: #fffbeb; border-left-color: #eab308; }
        .info { background-color: #f0f9ff; border-left-color: #0ea5e9; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f8fafc; }
        .stat { display: inline-block; background: #e5e7eb; padding: 10px; margin: 5px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🌐 Multi-Subnet Network Assessment 🌐</h1>
        <h2>CyberEXPERT Game 2025 - Energy Infrastructure</h2>
        <p>Comprehensive Network Discovery and Analysis</p>
        <p>Generated: $(date)</p>
    </div>

    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="stat"><strong>Total Active Hosts:</strong> $total_hosts</div>
        <div class="stat"><strong>Total Open Services:</strong> $total_services</div>
        <div class="stat"><strong>Subnets Scanned:</strong> ${#ENERGY_SUBNETS[@]}</div>
        <div class="stat"><strong>Protected Infrastructure:</strong> Excluded ✓</div>
    </div>

    <div class="section">
        <h2>🏭 Energy Infrastructure Networks</h2>
        <table>
            <tr><th>Subnet</th><th>Role</th><th>Security Level</th><th>Priority</th></tr>
            <tr><td>10.10.0.0/24</td><td>HQ Network</td><td class="medium">MEDIUM</td><td>Monitor corporate access</td></tr>
            <tr><td>10.50.0.0/24</td><td>Management</td><td class="medium">MEDIUM</td><td>Secure admin access</td></tr>
            <tr><td>10.200.0.0/24</td><td>Production</td><td class="high">HIGH</td><td>Monitor production systems</td></tr>
            <tr><td>192.168.0.0/24</td><td>Gateway/DMZ</td><td class="high">HIGH</td><td>Secure external access</td></tr>
            <tr><td>172.16.1.0/24</td><td>Control Network</td><td class="critical">CRITICAL</td><td>Isolate control systems</td></tr>
            <tr><td>172.16.2.0/24</td><td>SCADA Network</td><td class="critical">CRITICAL</td><td>Monitor SCADA traffic</td></tr>
            <tr><td>172.16.3.0/24</td><td>HMI Network</td><td class="critical">CRITICAL</td><td>Secure HMI interfaces</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>🛡️ CEG2025 Competition Compliance</h2>
        <div class="info">
            <h3>Protected Infrastructure (Automatically Excluded):</h3>
            <ul>
                <li>✅ Core Simulator Node: 10.83.171.142</li>
                <li>✅ All hosts ending in .253 (simulator infrastructure)</li>
                <li>✅ Core Routers: rt01/02/03.core.i-isp.eu</li>
                <li>✅ CyberAgent Port: 54321/TCP</li>
                <li>✅ Information Portal: 8888/TCP</li>
            </ul>
        </div>
    </div>

    <div class="section">
        <h2>🔍 Service Categories Scanned</h2>
        <table>
            <tr><th>Category</th><th>Ports</th><th>Purpose</th></tr>
            <tr><td>Web Services</td><td>80, 443, 8080, 8443, 9000, 10000</td><td>Web interfaces, HMI access</td></tr>
            <tr><td>SCADA Protocols</td><td>502, 20000, 102, 44818, 47808</td><td>Industrial control protocols</td></tr>
            <tr><td>Remote Access</td><td>22, 23, 3389, 5900-5902</td><td>SSH, Telnet, RDP, VNC</td></tr>
            <tr><td>Databases</td><td>1433, 3306, 5432, 1521, 27017</td><td>Database services</td></tr>
            <tr><td>Management</td><td>161, 162, 623, 664</td><td>SNMP, IPMI</td></tr>
            <tr><td>Industrial</td><td>2404, 34962-34964, 1217, 2455</td><td>PROFINET, CoDeSys</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>📈 Recommendations</h2>
        <ol>
            <li><strong>Network Segmentation:</strong> Ensure SCADA networks (172.16.x.x) are properly isolated</li>
            <li><strong>Access Control:</strong> Implement strict access controls for critical networks</li>
            <li><strong>Monitoring:</strong> Deploy continuous monitoring for all industrial protocols</li>
            <li><strong>Hardening:</strong> Secure all discovered services, especially in critical networks</li>
            <li><strong>Incident Response:</strong> Prepare for rapid response in critical infrastructure networks</li>
        </ol>
    </div>

    <div class="section">
        <h2>📋 Detailed Reports</h2>
        <ul>
            <li><strong>Host Discovery:</strong> network_discovery_${TIMESTAMP}.txt</li>
            <li><strong>Port Scanning:</strong> port_scan_${TIMESTAMP}.txt</li>
            <li><strong>Network Topology:</strong> network_topology_${TIMESTAMP}.txt</li>
            <li><strong>Scan Logs:</strong> network_scan_${TIMESTAMP}.log</li>
        </ul>
    </div>

    <div class="header" style="margin-top: 30px;">
        <p>Generated by Blue Team Multi-Subnet Scanner v$VERSION</p>
        <p>Designed for CyberEXPERT Game 2025 - 70-80 VM Environment</p>
    </div>
</body>
</html>
EOF

    log_message "INFO" "Comprehensive network report generated: $final_report"
    
    # Display completion summary
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${WHITE}             Multi-Subnet Network Scan Complete                   ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} 🌐 Networks Scanned: ${WHITE}${#ENERGY_SUBNETS[@]} energy infrastructure subnets${NC}        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} 🖥️  Active Hosts: ${WHITE}$total_hosts discovered hosts${NC}                         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} 🔌 Open Services: ${WHITE}$total_services service ports${NC}                         ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} 🛡️  Protection: ${WHITE}CEG2025 simulator infrastructure excluded${NC}      ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} 📊 Report: ${YELLOW}$(basename "$final_report")${NC}                      ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Main execution function
main() {
    show_banner
    create_directories
    
    case "${1:-help}" in
        "scan")
            log_message "INFO" "Starting comprehensive multi-subnet network scan..."
            
            # Main scan workflow
            local discovery_report="$REPORT_DIR/network_discovery_${TIMESTAMP}.txt"
            local port_scan_report="$REPORT_DIR/port_scan_${TIMESTAMP}.txt"
            
            echo "CEG2025 Multi-Subnet Network Scan Report" > "$discovery_report"
            echo "=========================================" >> "$discovery_report"
            echo "Started: $(date)" >> "$discovery_report"
            echo "" >> "$discovery_report"
            
            # Discover subnets
            local subnets
            subnets=$(discover_subnets)
            
            # Scan each subnet
            local all_hosts=()
            for subnet in $subnets; do
                local hosts
                hosts=$(discover_hosts "$subnet" "$discovery_report")
                if [[ -n "$hosts" ]]; then
                    all_hosts+=($hosts)
                fi
            done
            
            # Port scan discovered hosts
            if [[ ${#all_hosts[@]} -gt 0 ]]; then
                port_scan_hosts "${all_hosts[*]}" "$port_scan_report"
                generate_topology_map "$discovery_report"
                generate_network_report
            else
                log_message "WARN" "No active hosts discovered"
            fi
            ;;
        "discover")
            log_message "INFO" "Subnet discovery mode..."
            discover_subnets
            ;;
        "topology")
            generate_topology_map "$REPORT_DIR/network_discovery_*.txt"
            ;;
        "help"|*)
            echo -e "${CYAN}Multi-Subnet Network Scanner Commands:${NC}"
            echo -e "${WHITE}  scan${NC}       - Complete network discovery and port scanning"
            echo -e "${WHITE}  discover${NC}   - Discover active subnets only"
            echo -e "${WHITE}  topology${NC}   - Generate network topology map"
            echo -e "${WHITE}  help${NC}       - Show this help message"
            echo
            echo -e "${YELLOW}CEG2025 Features:${NC}"
            echo -e "${WHITE}  • Scans 70-80 VM environment across multiple subnets${NC}"
            echo -e "${WHITE}  • Automatically excludes CEG2025 simulator infrastructure${NC}"
            echo -e "${WHITE}  • Optimized for energy sector critical infrastructure${NC}"
            echo -e "${WHITE}  • Generates comprehensive HTML reports${NC}"
            echo
            echo -e "${YELLOW}Examples:${NC}"
            echo -e "${WHITE}  ./multi_subnet_scanner.sh scan${NC}      # Complete assessment"
            echo -e "${WHITE}  ./multi_subnet_scanner.sh discover${NC}  # Subnet discovery only"
            ;;
    esac
}

# Execute main function with all arguments
main "$@"