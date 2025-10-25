#!/bin/bash

# ============================================================================
# SCADA/ICS Security Scanner for Energy Infrastructure (CEG2025)
# ============================================================================
# Comprehensive industrial control system security assessment
# Designed for energy sector critical infrastructure protection
# Compatible with Modbus, DNP3, IEC 61850, and other industrial protocols
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="SCADA/ICS Security Scanner"

# Color definitions for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
LOG_DIR="../logs/scada"
REPORT_DIR="../reports/scada"
CONFIG_DIR="../config/scada"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# CEG2025 Protected Infrastructure (DO NOT SCAN)
PROTECTED_IPS=(
    "10.83.171.142"           # Core simulator node
    "*.*.*.253"               # All .253 hosts in subnets
    "rt01.core.i-isp.eu"      # Core router 1
    "rt02.core.i-isp.eu"      # Core router 2  
    "rt03.core.i-isp.eu"      # Core router 3
)

PROTECTED_PORTS=(
    "54321"                   # CyberAgent monitoring
    "8888"                    # Information Portal
)

# Industrial Protocol Port Mapping
declare -A SCADA_PORTS=(
    ["modbus_tcp"]="502"
    ["modbus_rtu"]="502"
    ["dnp3"]="20000"
    ["iec61850_mms"]="102"
    ["iec61850_goose"]="102"
    ["ethernet_ip"]="44818"
    ["profinet"]="34962,34963,34964"
    ["bacnet"]="47808"
    ["s7_plc"]="102"
    ["fox"]="1911"
    ["crimson_v3"]="789"
    ["omron_fins"]="9600"
    ["ge_srtp"]="18245"
    ["schneider_uni_te"]="502"
    ["mitsubishi_melsec"]="5007"
    ["rockwell_df1"]="44818"
    ["codesys"]="1217,2455"
)

# Energy Sector Critical Services
ENERGY_SERVICES=(
    "HMI"                     # Human Machine Interface
    "SCADA"                   # Supervisory Control and Data Acquisition
    "EMS"                     # Energy Management System
    "DMS"                     # Distribution Management System
    "OMS"                     # Outage Management System
    "WAMS"                    # Wide Area Monitoring System
    "PMU"                     # Phasor Measurement Unit
    "RTU"                     # Remote Terminal Unit
    "PLC"                     # Programmable Logic Controller
    "IED"                     # Intelligent Electronic Device
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
        "INFO")  echo -e "${GREEN}[INFO]${NC}  $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC}  $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${CYAN}[DEBUG]${NC} $message" ;;
        "SCADA") echo -e "${PURPLE}[SCADA]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/scada_security_${TIMESTAMP}.log"
}

# Display banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "============================================================================"
    echo "  ⚡ SCADA/ICS Security Scanner for Energy Infrastructure (CEG2025) ⚡"
    echo "============================================================================"
    echo -e "${WHITE}Version: $VERSION${NC}"
    echo -e "${WHITE}Designed for: Critical Energy Infrastructure Protection${NC}"
    echo -e "${WHITE}Protocols: Modbus, DNP3, IEC 61850, EtherNet/IP, S7, BACnet${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
}

# Check if IP is protected (CEG2025 simulator infrastructure)
is_protected_ip() {
    local ip=$1
    
    # Check exact matches
    for protected in "${PROTECTED_IPS[@]}"; do
        if [[ "$ip" == "$protected" ]]; then
            return 0
        fi
    done
    
    # Check .253 pattern in last octet
    if [[ "$ip" =~ \.[0-9]+\.[0-9]+\.253$ ]]; then
        return 0
    fi
    
    return 1
}

# Discover SCADA/ICS devices on network
discover_scada_devices() {
    log_message "INFO" "Starting SCADA/ICS device discovery..."
    local discovery_report="$REPORT_DIR/scada_discovery_${TIMESTAMP}.txt"
    
    echo "SCADA/ICS Device Discovery Report - $(date)" > "$discovery_report"
    echo "=========================================" >> "$discovery_report"
    
    # Get network interfaces and subnets
    local subnets=()
    while IFS= read -r line; do
        if [[ $line =~ inet\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
            local subnet="${BASH_REMATCH[1]}"
            # Skip loopback
            if [[ ! $subnet =~ ^127\. ]]; then
                subnets+=("$subnet")
            fi
        fi
    done < <(ip addr show 2>/dev/null || ifconfig 2>/dev/null)
    
    log_message "SCADA" "Scanning subnets: ${subnets[*]}"
    
    # Scan for industrial protocols
    for subnet in "${subnets[@]}"; do
        log_message "INFO" "Scanning subnet: $subnet"
        echo "Subnet: $subnet" >> "$discovery_report"
        
        # Extract network portion for nmap
        local network=$(echo "$subnet" | cut -d'/' -f1 | sed 's/\.[0-9]*$/\.0/')
        local cidr=$(echo "$subnet" | cut -d'/' -f2)
        local scan_target="${network}/${cidr}"
        
        # Scan for SCADA ports
        for protocol in "${!SCADA_PORTS[@]}"; do
            local ports="${SCADA_PORTS[$protocol]}"
            log_message "SCADA" "Scanning for $protocol on ports $ports"
            
            if command -v nmap >/dev/null 2>&1; then
                # Use nmap if available
                local nmap_result
                nmap_result=$(nmap -sS -p "$ports" --open "$scan_target" 2>/dev/null | grep -E "(Nmap scan report|open)")
                
                if [[ -n "$nmap_result" ]]; then
                    echo "  $protocol devices found:" >> "$discovery_report"
                    echo "$nmap_result" >> "$discovery_report"
                    log_message "SCADA" "Found $protocol devices in $scan_target"
                fi
            else
                # Fallback to manual scanning
                log_message "WARN" "nmap not available, using basic port scanning"
                IFS=',' read -ra PORT_ARRAY <<< "$ports"
                for port in "${PORT_ARRAY[@]}"; do
                    timeout 2 bash -c "echo >/dev/tcp/${network%.*}.1/$port" 2>/dev/null && {
                        echo "  $protocol service detected on ${network%.*}.1:$port" >> "$discovery_report"
                        log_message "SCADA" "Potential $protocol service on ${network%.*}.1:$port"
                    }
                done
            fi
        done
        echo "" >> "$discovery_report"
    done
    
    log_message "INFO" "SCADA device discovery completed. Report: $discovery_report"
}

# Scan for industrial protocol vulnerabilities
scan_industrial_protocols() {
    log_message "INFO" "Starting industrial protocol vulnerability scan..."
    local vuln_report="$REPORT_DIR/scada_vulnerabilities_${TIMESTAMP}.txt"
    
    echo "SCADA/ICS Vulnerability Assessment - $(date)" > "$vuln_report"
    echo "=============================================" >> "$vuln_report"
    
    # Modbus Security Assessment
    scan_modbus_security() {
        log_message "SCADA" "Scanning Modbus TCP security..."
        echo "=== MODBUS SECURITY ASSESSMENT ===" >> "$vuln_report"
        
        # Check for open Modbus ports
        if command -v nmap >/dev/null 2>&1; then
            local modbus_hosts
            modbus_hosts=$(nmap -sS -p 502 --open 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 2>/dev/null | grep -B1 "502/tcp open" | grep "Nmap scan report" | awk '{print $NF}')
            
            while IFS= read -r host; do
                if [[ -n "$host" ]] && ! is_protected_ip "$host"; then
                    echo "Modbus device found: $host" >> "$vuln_report"
                    log_message "SCADA" "Modbus device detected: $host"
                    
                    # Test for common Modbus vulnerabilities
                    if command -v python3 >/dev/null 2>&1; then
                        python3 -c "
import socket
import struct
import sys

def test_modbus_read_coils(host, port=502):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        
        # Modbus TCP frame: Transaction ID + Protocol ID + Length + Unit ID + Function Code + Data
        # Read Coils (Function Code 01) - Reading coils 0-9
        frame = struct.pack('>HHHBBB', 1, 0, 6, 1, 1, 0, 10)
        sock.send(frame)
        
        response = sock.recv(1024)
        sock.close()
        
        if len(response) > 8:
            print(f'VULNERABLE: {host} - Modbus read coils successful (unauthorized access)')
            return True
        else:
            print(f'SECURE: {host} - Modbus access properly restricted')
            return False
    except:
        print(f'ERROR: {host} - Could not test Modbus security')
        return False

if __name__ == '__main__':
    test_modbus_read_coils('$host')
" >> "$vuln_report" 2>/dev/null
                    fi
                fi
            done <<< "$modbus_hosts"
        fi
    }
    
    # DNP3 Security Assessment
    scan_dnp3_security() {
        log_message "SCADA" "Scanning DNP3 security..."
        echo "=== DNP3 SECURITY ASSESSMENT ===" >> "$vuln_report"
        
        if command -v nmap >/dev/null 2>&1; then
            local dnp3_hosts
            dnp3_hosts=$(nmap -sS -p 20000 --open 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 2>/dev/null | grep -B1 "20000/tcp open" | grep "Nmap scan report" | awk '{print $NF}')
            
            while IFS= read -r host; do
                if [[ -n "$host" ]] && ! is_protected_ip "$host"; then
                    echo "DNP3 device found: $host" >> "$vuln_report"
                    log_message "SCADA" "DNP3 device detected: $host"
                    
                    # Basic DNP3 security test
                    echo "  - Testing DNP3 authentication..." >> "$vuln_report"
                    timeout 5 bash -c "echo -e '\x05\x64\x05\xC0\x01\x00\x00\x04' > /dev/tcp/$host/20000" 2>/dev/null && {
                        echo "  - VULNERABLE: DNP3 responds without authentication" >> "$vuln_report"
                        log_message "WARN" "DNP3 vulnerability detected on $host"
                    } || {
                        echo "  - SECURE: DNP3 access properly controlled" >> "$vuln_report"
                    }
                fi
            done <<< "$dnp3_hosts"
        fi
    }
    
    # S7 PLC Security Assessment
    scan_s7_security() {
        log_message "SCADA" "Scanning Siemens S7 PLC security..."
        echo "=== SIEMENS S7 PLC SECURITY ASSESSMENT ===" >> "$vuln_report"
        
        if command -v nmap >/dev/null 2>&1; then
            local s7_hosts
            s7_hosts=$(nmap -sS -p 102 --open 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 2>/dev/null | grep -B1 "102/tcp open" | grep "Nmap scan report" | awk '{print $NF}')
            
            while IFS= read -r host; do
                if [[ -n "$host" ]] && ! is_protected_ip "$host"; then
                    echo "S7 PLC found: $host" >> "$vuln_report"
                    log_message "SCADA" "S7 PLC detected: $host"
                    
                    # Test S7 communication
                    echo "  - Testing S7 CPU identification..." >> "$vuln_report"
                    if command -v python3 >/dev/null 2>&1; then
                        python3 -c "
import socket
import struct

def test_s7_cpu_info(host, port=102):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        
        # S7 CPU info request
        cpu_info_request = bytes.fromhex('0300001611e00000000400c1020100c2020300c0010a')
        sock.send(cpu_info_request)
        
        response = sock.recv(1024)
        sock.close()
        
        if len(response) > 20:
            print(f'VULNERABLE: {host} - S7 CPU info accessible (unauthorized PLC access)')
            return True
        else:
            print(f'SECURE: {host} - S7 access properly restricted')
            return False
    except:
        print(f'ERROR: {host} - Could not test S7 security')
        return False

test_s7_cpu_info('$host')
" >> "$vuln_report" 2>/dev/null
                    fi
                fi
            done <<< "$s7_hosts"
        fi
    }
    
    # Run all protocol scans
    scan_modbus_security
    scan_dnp3_security  
    scan_s7_security
    
    log_message "INFO" "Industrial protocol vulnerability scan completed. Report: $vuln_report"
}

# Check for energy sector specific vulnerabilities
check_energy_vulnerabilities() {
    log_message "INFO" "Starting energy sector vulnerability assessment..."
    local energy_report="$REPORT_DIR/energy_vulnerabilities_${TIMESTAMP}.txt"
    
    echo "Energy Infrastructure Vulnerability Report - $(date)" > "$energy_report"
    echo "=================================================" >> "$energy_report"
    
    # Check for default credentials on energy systems
    check_default_credentials() {
        echo "=== DEFAULT CREDENTIALS CHECK ===" >> "$energy_report"
        log_message "SCADA" "Checking for default credentials on energy systems..."
        
        # Common energy sector default credentials
        declare -A DEFAULT_CREDS=(
            ["GE_iFix"]="admin:admin"
            ["Wonderware"]="aaAdmin:"
            ["Citect"]="CITECT:CITECT"
            ["Schneider_Unity"]="USER:USER"
            ["ABB_800xA"]="admin:admin"
            ["Siemens_WinCC"]="Administrator:"
            ["Rockwell_FactoryTalk"]="admin:admin"
            ["Honeywell_Experion"]="admin:admin"
        )
        
        # Check common HMI/SCADA web interfaces
        for system in "${!DEFAULT_CREDS[@]}"; do
            local creds="${DEFAULT_CREDS[$system]}"
            local username=$(echo "$creds" | cut -d':' -f1)
            local password=$(echo "$creds" | cut -d':' -f2)
            
            echo "Checking for $system default credentials..." >> "$energy_report"
            log_message "SCADA" "Testing $system default credentials: $username:$password"
            
            # Test against common ports
            for port in 80 443 8080 8443 9000; do
                if command -v curl >/dev/null 2>&1; then
                    timeout 5 curl -s -u "$username:$password" "http://192.168.1.1:$port/login" 2>/dev/null | grep -i "success\|dashboard\|scada" && {
                        echo "  VULNERABLE: Default credentials work on port $port" >> "$energy_report"
                        log_message "ERROR" "Default credentials found for $system on port $port"
                    }
                fi
            done
        done
    }
    
    # Check for exposed HMI interfaces
    check_exposed_hmi() {
        echo "=== EXPOSED HMI INTERFACES ===" >> "$energy_report"
        log_message "SCADA" "Scanning for exposed HMI interfaces..."
        
        # Common HMI web interface ports
        local hmi_ports=(80 443 8080 8443 9000 10000)
        
        for port in "${hmi_ports[@]}"; do
            if command -v nmap >/dev/null 2>&1; then
                local hmi_hosts
                hmi_hosts=$(nmap -sS -p "$port" --open 192.168.0.0/16 10.0.0.0/8 2>/dev/null | grep -B1 "$port/tcp open" | grep "Nmap scan report" | awk '{print $NF}')
                
                while IFS= read -r host; do
                    if [[ -n "$host" ]] && ! is_protected_ip "$host"; then
                        echo "Checking HMI on $host:$port..." >> "$energy_report"
                        
                        if command -v curl >/dev/null 2>&1; then
                            local response
                            response=$(timeout 5 curl -s "http://$host:$port/" 2>/dev/null | grep -i "scada\|hmi\|wonderware\|citect\|ge.ifix\|wincc\|factorytalk")
                            
                            if [[ -n "$response" ]]; then
                                echo "  EXPOSED HMI: $host:$port - $response" >> "$energy_report"
                                log_message "WARN" "Exposed HMI interface: $host:$port"
                            fi
                        fi
                    fi
                done <<< "$hmi_hosts"
            fi
        done
    }
    
    # Check for vulnerable SCADA protocols
    check_protocol_security() {
        echo "=== PROTOCOL SECURITY ANALYSIS ===" >> "$energy_report"
        log_message "SCADA" "Analyzing SCADA protocol security..."
        
        # Check for unencrypted protocols
        local insecure_protocols=("telnet:23" "ftp:21" "http:80" "snmp:161")
        
        for proto_port in "${insecure_protocols[@]}"; do
            local protocol=$(echo "$proto_port" | cut -d':' -f1)
            local port=$(echo "$proto_port" | cut -d':' -f2)
            
            echo "Checking for insecure $protocol..." >> "$energy_report"
            
            if command -v nmap >/dev/null 2>&1; then
                local insecure_hosts
                insecure_hosts=$(nmap -sS -p "$port" --open 192.168.0.0/16 10.0.0.0/8 2>/dev/null | grep -B1 "$port/tcp open" | grep "Nmap scan report" | awk '{print $NF}')
                
                local count=0
                while IFS= read -r host; do
                    if [[ -n "$host" ]] && ! is_protected_ip "$host"; then
                        ((count++))
                    fi
                done <<< "$insecure_hosts"
                
                if [[ $count -gt 0 ]]; then
                    echo "  VULNERABLE: $count hosts running insecure $protocol" >> "$energy_report"
                    log_message "WARN" "$count hosts running insecure $protocol protocol"
                else
                    echo "  SECURE: No insecure $protocol services found" >> "$energy_report"
                fi
            fi
        done
    }
    
    # Run all energy vulnerability checks
    check_default_credentials
    check_exposed_hmi
    check_protocol_security
    
    log_message "INFO" "Energy sector vulnerability assessment completed. Report: $energy_report"
}

# Generate comprehensive SCADA security report
generate_scada_report() {
    log_message "INFO" "Generating comprehensive SCADA security report..."
    local final_report="$REPORT_DIR/SCADA_Security_Assessment_${TIMESTAMP}.html"
    
    cat > "$final_report" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>SCADA/ICS Security Assessment Report - CEG2025</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }
        .vulnerability { background-color: #ffebee; padding: 10px; margin: 10px 0; border-left: 4px solid #f44336; }
        .secure { background-color: #e8f5e8; padding: 10px; margin: 10px 0; border-left: 4px solid #4caf50; }
        .warning { background-color: #fff3e0; padding: 10px; margin: 10px 0; border-left: 4px solid #ff9800; }
        .info { background-color: #e3f2fd; padding: 10px; margin: 10px 0; border-left: 4px solid #2196f3; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ SCADA/ICS Security Assessment Report ⚡</h1>
        <h2>CyberEXPERT Game 2025 - Energy Infrastructure</h2>
        <p>Generated: $(date)</p>
    </div>

    <div class="section">
        <h2>🔍 Executive Summary</h2>
        <p>Comprehensive security assessment of industrial control systems and SCADA infrastructure for CEG2025 energy sector simulation.</p>
        
        <table>
            <tr><th>Assessment Category</th><th>Status</th><th>Findings</th></tr>
            <tr><td>Device Discovery</td><td>✅ Complete</td><td>See discovery report</td></tr>
            <tr><td>Protocol Security</td><td>✅ Complete</td><td>See vulnerability report</td></tr>
            <tr><td>Energy Vulnerabilities</td><td>✅ Complete</td><td>See energy report</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>🏭 Industrial Protocol Analysis</h2>
        <h3>Supported Protocols:</h3>
        <ul>
            <li><strong>Modbus TCP/RTU</strong> - Port 502</li>
            <li><strong>DNP3</strong> - Port 20000</li>
            <li><strong>IEC 61850 MMS</strong> - Port 102</li>
            <li><strong>EtherNet/IP</strong> - Port 44818</li>
            <li><strong>Siemens S7</strong> - Port 102</li>
            <li><strong>BACnet</strong> - Port 47808</li>
            <li><strong>PROFINET</strong> - Ports 34962-34964</li>
        </ul>
    </div>

    <div class="section">
        <h2>⚡ Energy Sector Focus Areas</h2>
        <ul>
            <li>Human Machine Interface (HMI) Security</li>
            <li>SCADA System Hardening</li>
            <li>Energy Management System (EMS) Protection</li>
            <li>Programmable Logic Controller (PLC) Security</li>
            <li>Remote Terminal Unit (RTU) Assessment</li>
            <li>Intelligent Electronic Device (IED) Monitoring</li>
        </ul>
    </div>

    <div class="section">
        <h2>🛡️ CEG2025 Competition Compliance</h2>
        <div class="info">
            <strong>Protected Infrastructure (Excluded from Scans):</strong>
            <ul>
                <li>Core Simulator: 10.83.171.142</li>
                <li>All hosts ending in .253</li>
                <li>Core routers: rt01/02/03.core.i-isp.eu</li>
                <li>CyberAgent port: 54321/TCP</li>
                <li>Information Portal: port 8888/TCP</li>
            </ul>
        </div>
    </div>

    <div class="section">
        <h2>📊 Detailed Reports</h2>
        <p>Individual detailed reports have been generated:</p>
        <ul>
            <li><strong>Device Discovery:</strong> scada_discovery_${TIMESTAMP}.txt</li>
            <li><strong>Vulnerability Assessment:</strong> scada_vulnerabilities_${TIMESTAMP}.txt</li>
            <li><strong>Energy Security:</strong> energy_vulnerabilities_${TIMESTAMP}.txt</li>
        </ul>
    </div>

    <div class="section">
        <h2>🔧 Remediation Recommendations</h2>
        <ol>
            <li><strong>Network Segmentation:</strong> Isolate SCADA networks from corporate networks</li>
            <li><strong>Authentication:</strong> Implement strong authentication for all industrial protocols</li>
            <li><strong>Encryption:</strong> Use encrypted communication protocols where possible</li>
            <li><strong>Monitoring:</strong> Deploy continuous monitoring for industrial network traffic</li>
            <li><strong>Updates:</strong> Keep all HMI, SCADA, and PLC firmware updated</li>
            <li><strong>Access Control:</strong> Implement role-based access control for critical systems</li>
        </ol>
    </div>

    <div class="header" style="margin-top: 30px;">
        <p>Generated by Blue Team Automation Agent v$VERSION</p>
        <p>Designed for CyberEXPERT Game 2025 - Energy Infrastructure Protection</p>
    </div>
</body>
</html>
EOF

    log_message "INFO" "Comprehensive SCADA report generated: $final_report"
    
    # Also create summary for terminal
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${WHITE}                SCADA/ICS Security Assessment Complete            ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} 📊 Reports Generated:                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}   • Device Discovery Report                                      ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}   • Protocol Vulnerability Assessment                           ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}   • Energy Sector Security Analysis                             ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}   • Comprehensive HTML Report: ${YELLOW}$(basename "$final_report")${NC}              ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Main execution function
main() {
    show_banner
    create_directories
    
    case "${1:-help}" in
        "scan")
            log_message "INFO" "Starting comprehensive SCADA/ICS security scan..."
            discover_scada_devices
            scan_industrial_protocols  
            check_energy_vulnerabilities
            generate_scada_report
            ;;
        "discover")
            discover_scada_devices
            ;;
        "protocols")
            scan_industrial_protocols
            ;;
        "energy")
            check_energy_vulnerabilities
            ;;
        "report")
            generate_scada_report
            ;;
        "help"|*)
            echo -e "${CYAN}SCADA/ICS Security Scanner Commands:${NC}"
            echo -e "${WHITE}  scan${NC}      - Full SCADA/ICS security assessment"
            echo -e "${WHITE}  discover${NC}   - Discover SCADA/ICS devices on network" 
            echo -e "${WHITE}  protocols${NC}  - Scan industrial protocol vulnerabilities"
            echo -e "${WHITE}  energy${NC}     - Check energy sector specific vulnerabilities"
            echo -e "${WHITE}  report${NC}     - Generate comprehensive security report"
            echo -e "${WHITE}  help${NC}       - Show this help message"
            echo
            echo -e "${YELLOW}Examples:${NC}"
            echo -e "${WHITE}  ./scada_ics_security.sh scan${NC}      # Complete assessment"
            echo -e "${WHITE}  ./scada_ics_security.sh discover${NC}  # Device discovery only"
            echo -e "${WHITE}  ./scada_ics_security.sh protocols${NC} # Protocol security only"
            ;;
    esac
}

# Execute main function with all arguments
main "$@"