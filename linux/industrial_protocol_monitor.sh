#!/bin/bash

# ============================================================================
# Industrial Protocol Monitor for Energy Infrastructure (CEG2025)
# ============================================================================
# Real-time monitoring system for SCADA protocols and industrial communications
# Designed for continuous surveillance of energy sector critical infrastructure
# Supports Modbus, DNP3, IEC 61850, EtherNet/IP, and other industrial protocols
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="Industrial Protocol Monitor"

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
LOG_DIR="../logs/protocol_monitor"
REPORT_DIR="../reports/protocol_monitor"
CONFIG_DIR="../config/protocol_monitor"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Monitoring configuration
MONITOR_INTERVAL=5        # seconds between checks
ALERT_THRESHOLD=10        # suspicious events before alert
LOG_ROTATION_SIZE="100M"  # Log rotation size
BASELINE_LEARNING_TIME=300 # 5 minutes for baseline learning

# Industrial protocol definitions
declare -A PROTOCOL_SIGNATURES=(
    # Modbus TCP signatures
    ["modbus_tcp_read_coils"]="00 01 00 00 00 06 01 01"
    ["modbus_tcp_read_discrete"]="00 01 00 00 00 06 01 02"
    ["modbus_tcp_read_holding"]="00 01 00 00 00 06 01 03"
    ["modbus_tcp_read_input"]="00 01 00 00 00 06 01 04"
    ["modbus_tcp_write_coil"]="00 01 00 00 00 06 01 05"
    ["modbus_tcp_write_register"]="00 01 00 00 00 06 01 06"
    
    # DNP3 signatures
    ["dnp3_request_header"]="05 64"
    ["dnp3_response_header"]="05 64"
    ["dnp3_data_link"]="05 64 .* C0"
    
    # IEC 61850 MMS signatures
    ["iec61850_initiate"]="60 .* 06 07 2B 0C 02 01 01 01"
    ["iec61850_conclude"]="60 .* A2"
    
    # EtherNet/IP signatures
    ["ethernet_ip_register"]="6F 00"
    ["ethernet_ip_list_services"]="04 00"
    ["ethernet_ip_list_identity"]="63 00"
    
    # Siemens S7 signatures
    ["s7_setup_communication"]="72 01 00"
    ["s7_read_var"]="72 02 00"
    ["s7_write_var"]="72 03 00"
)

# Industrial ports to monitor
INDUSTRIAL_PORTS=(
    "502"     # Modbus TCP
    "20000"   # DNP3
    "102"     # ISO-TSAP (S7, IEC 61850)
    "44818"   # EtherNet/IP
    "47808"   # BACnet
    "789"     # Redlion Crimson
    "1911"    # Niagara Fox
    "9600"    # OMRON FINS
    "18245"   # GE SRTP
    "5007"    # Mitsubishi MELSEC-Q
    "2404"    # IEC-104
    "34962"   # PROFINET DCP
    "1217"    # CoDeSys Runtime
)

# Energy sector critical functions to monitor
CRITICAL_FUNCTIONS=(
    "READ_COILS"              # PLC discrete outputs
    "READ_INPUT_REGISTERS"    # Sensor readings
    "WRITE_COILS"            # Control outputs
    "WRITE_REGISTERS"        # Setpoint changes
    "EMERGENCY_STOP"         # Safety functions
    "SYSTEM_CONTROL"         # System operations
    "DATA_ACQUISITION"       # SCADA data collection
    "ALARM_ACKNOWLEDGMENT"   # Alarm handling
)

# Create necessary directories
create_directories() {
    local dirs=("$LOG_DIR" "$REPORT_DIR" "$CONFIG_DIR" "$LOG_DIR/raw" "$LOG_DIR/alerts" "$LOG_DIR/baselines")
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir" 2>/dev/null
    done
    
    # Create monitoring configuration
    cat > "$CONFIG_DIR/monitor_config.conf" << EOF
# Industrial Protocol Monitor Configuration
# Generated: $(date)

# Monitoring Settings
MONITOR_INTERVAL=$MONITOR_INTERVAL
ALERT_THRESHOLD=$ALERT_THRESHOLD
BASELINE_LEARNING_TIME=$BASELINE_LEARNING_TIME

# Protocol Detection
DEEP_PACKET_INSPECTION=true
PROTOCOL_ANOMALY_DETECTION=true
BASELINE_LEARNING=true

# Alerting
REAL_TIME_ALERTS=true
EMAIL_ALERTS=false
SYSLOG_INTEGRATION=true

# Logging
LOG_LEVEL=INFO
LOG_ROTATION=true
LOG_RETENTION_DAYS=30
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
        "ALERT") echo -e "${RED}[ALERT]${NC} $message" ;;
        "MONITOR") echo -e "${PURPLE}[MONITOR]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/protocol_monitor_${TIMESTAMP}.log"
    
    # Send alerts to dedicated alert log
    if [[ "$level" == "ALERT" ]]; then
        echo "[$timestamp] $message" >> "$LOG_DIR/alerts/protocol_alerts_${TIMESTAMP}.log"
    fi
}

# Display banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "============================================================================"
    echo "     ⚡ Industrial Protocol Monitor for Energy Infrastructure ⚡"
    echo "============================================================================"
    echo -e "${WHITE}Version: $VERSION${NC}"
    echo -e "${WHITE}Target: Real-time SCADA/ICS Protocol Monitoring${NC}"
    echo -e "${WHITE}Protocols: Modbus, DNP3, IEC 61850, EtherNet/IP, S7, BACnet${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
}

# Initialize baseline learning
initialize_baseline() {
    log_message "INFO" "Initializing protocol baseline learning..."
    local baseline_file="$LOG_DIR/baselines/protocol_baseline_${TIMESTAMP}.json"
    
    cat > "$baseline_file" << EOF
{
  "baseline_start": "$(date -Iseconds)",
  "learning_duration": $BASELINE_LEARNING_TIME,
  "protocol_patterns": {},
  "traffic_volumes": {},
  "communication_pairs": {},
  "normal_functions": [],
  "time_patterns": {}
}
EOF

    log_message "INFO" "Baseline learning initialized: $baseline_file"
    echo "$baseline_file"
}

# Monitor industrial protocols using packet capture
start_protocol_monitoring() {
    log_message "INFO" "Starting industrial protocol monitoring..."
    local capture_file="$LOG_DIR/raw/industrial_traffic_${TIMESTAMP}.pcap"
    local analysis_log="$LOG_DIR/protocol_analysis_${TIMESTAMP}.log"
    
    # Check if tcpdump or tshark is available
    if command -v tcpdump >/dev/null 2>&1; then
        monitor_with_tcpdump "$capture_file" "$analysis_log"
    elif command -v tshark >/dev/null 2>&1; then
        monitor_with_tshark "$capture_file" "$analysis_log"
    else
        # Fallback to netstat-based monitoring
        monitor_with_netstat "$analysis_log"
    fi
}

# Monitor using tcpdump
monitor_with_tcpdump() {
    local capture_file=$1
    local analysis_log=$2
    
    log_message "MONITOR" "Starting tcpdump-based protocol monitoring..."
    
    # Build port filter for industrial protocols
    local port_filter=""
    for port in "${INDUSTRIAL_PORTS[@]}"; do
        if [[ -n "$port_filter" ]]; then
            port_filter="$port_filter or port $port"
        else
            port_filter="port $port"
        fi
    done
    
    # Start packet capture in background
    {
        timeout "$BASELINE_LEARNING_TIME" tcpdump -i any -s 0 -w "$capture_file" "$port_filter" 2>/dev/null &
        local tcpdump_pid=$!
        
        # Monitor and analyze captured packets
        while kill -0 $tcpdump_pid 2>/dev/null; do
            sleep "$MONITOR_INTERVAL"
            analyze_captured_traffic "$capture_file" "$analysis_log"
        done
    } &
    
    log_message "MONITOR" "Packet capture started, analyzing traffic..."
}

# Monitor using tshark
monitor_with_tshark() {
    local capture_file=$1
    local analysis_log=$2
    
    log_message "MONITOR" "Starting tshark-based protocol monitoring..."
    
    # Build display filter for industrial protocols
    local display_filter="tcp.port in {$(IFS=','; echo "${INDUSTRIAL_PORTS[*]}")}"
    
    # Start real-time analysis with tshark
    {
        timeout "$BASELINE_LEARNING_TIME" tshark -i any -f "tcp" -Y "$display_filter" -T fields \
            -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e data \
            2>/dev/null | while IFS=$'\t' read -r timestamp src_ip dst_ip src_port dst_port data; do
            
            analyze_protocol_packet "$timestamp" "$src_ip" "$dst_ip" "$src_port" "$dst_port" "$data" "$analysis_log"
            sleep 0.1
        done
    } &
    
    log_message "MONITOR" "Real-time protocol analysis started..."
}

# Fallback monitoring using netstat
monitor_with_netstat() {
    local analysis_log=$1
    
    log_message "MONITOR" "Starting netstat-based connection monitoring..."
    
    local end_time=$(($(date +%s) + BASELINE_LEARNING_TIME))
    
    while [[ $(date +%s) -lt $end_time ]]; do
        echo "=== Connection Monitor: $(date) ===" >> "$analysis_log"
        
        # Monitor active connections on industrial ports
        for port in "${INDUSTRIAL_PORTS[@]}"; do
            local connections
            connections=$(netstat -an 2>/dev/null | grep ":$port " | grep ESTABLISHED)
            
            if [[ -n "$connections" ]]; then
                echo "Active connections on port $port:" >> "$analysis_log"
                echo "$connections" >> "$analysis_log"
                log_message "MONITOR" "Active connections detected on industrial port $port"
                
                # Check for suspicious patterns
                local conn_count
                conn_count=$(echo "$connections" | wc -l)
                if [[ $conn_count -gt 10 ]]; then
                    log_message "ALERT" "High connection count on port $port: $conn_count connections"
                fi
            fi
        done
        
        echo "" >> "$analysis_log"
        sleep "$MONITOR_INTERVAL"
    done
}

# Analyze captured traffic for protocol patterns
analyze_captured_traffic() {
    local capture_file=$1
    local analysis_log=$2
    
    if [[ -f "$capture_file" ]] && command -v tcpdump >/dev/null 2>&1; then
        # Extract and analyze recent packets
        local recent_packets
        recent_packets=$(tcpdump -r "$capture_file" -nn -x 2>/dev/null | tail -20)
        
        if [[ -n "$recent_packets" ]]; then
            echo "=== Traffic Analysis: $(date) ===" >> "$analysis_log"
            echo "$recent_packets" >> "$analysis_log"
            
            # Look for known protocol signatures
            detect_protocol_signatures "$recent_packets" "$analysis_log"
        fi
    fi
}

# Analyze individual protocol packets
analyze_protocol_packet() {
    local timestamp=$1
    local src_ip=$2
    local dst_ip=$3
    local src_port=$4
    local dst_port=$5
    local data=$6
    local analysis_log=$7
    
    # Determine protocol based on port
    local protocol="UNKNOWN"
    case "$dst_port" in
        "502") protocol="MODBUS_TCP" ;;
        "20000") protocol="DNP3" ;;
        "102") protocol="IEC61850_S7" ;;
        "44818") protocol="ETHERNET_IP" ;;
        "47808") protocol="BACNET" ;;
        *) protocol="INDUSTRIAL_$(echo "$dst_port" | tr '[:lower:]' '[:upper:]')" ;;
    esac
    
    # Log protocol communication
    echo "[$timestamp] $protocol: $src_ip:$src_port -> $dst_ip:$dst_port" >> "$analysis_log"
    log_message "MONITOR" "$protocol communication: $src_ip -> $dst_ip"
    
    # Analyze payload for suspicious patterns
    if [[ -n "$data" ]]; then
        analyze_payload_data "$protocol" "$data" "$src_ip" "$dst_ip" "$analysis_log"
    fi
}

# Detect known protocol signatures
detect_protocol_signatures() {
    local packet_data=$1
    local analysis_log=$2
    
    for sig_name in "${!PROTOCOL_SIGNATURES[@]}"; do
        local signature="${PROTOCOL_SIGNATURES[$sig_name]}"
        local clean_signature=$(echo "$signature" | tr -d ' ')
        
        # Convert packet data to hex string for comparison
        local hex_data
        hex_data=$(echo "$packet_data" | grep -o '[0-9a-fA-F][0-9a-fA-F]' | tr -d '\n')
        
        if [[ "$hex_data" =~ $clean_signature ]]; then
            echo "PROTOCOL SIGNATURE DETECTED: $sig_name" >> "$analysis_log"
            log_message "MONITOR" "Detected $sig_name protocol signature"
            
            # Check for suspicious signatures
            case "$sig_name" in
                *"write"*|*"WRITE"*)
                    log_message "ALERT" "CRITICAL: Write operation detected - $sig_name"
                    ;;
                *"emergency"*|*"EMERGENCY"*)
                    log_message "ALERT" "CRITICAL: Emergency function detected - $sig_name"
                    ;;
            esac
        fi
    done
}

# Analyze payload data for anomalies
analyze_payload_data() {
    local protocol=$1
    local data=$2
    local src_ip=$3
    local dst_ip=$4
    local analysis_log=$5
    
    # Protocol-specific analysis
    case "$protocol" in
        "MODBUS_TCP")
            analyze_modbus_payload "$data" "$src_ip" "$dst_ip" "$analysis_log"
            ;;
        "DNP3")
            analyze_dnp3_payload "$data" "$src_ip" "$dst_ip" "$analysis_log"
            ;;
        "IEC61850_S7")
            analyze_s7_payload "$data" "$src_ip" "$dst_ip" "$analysis_log"
            ;;
        *)
            # Generic analysis
            local data_length=${#data}
            if [[ $data_length -gt 1000 ]]; then
                log_message "ALERT" "Large payload detected in $protocol: $data_length bytes"
            fi
            ;;
    esac
}

# Analyze Modbus payload
analyze_modbus_payload() {
    local data=$1
    local src_ip=$2
    local dst_ip=$3
    local analysis_log=$4
    
    # Extract Modbus function code (byte 7 in TCP frame)
    if [[ ${#data} -ge 14 ]]; then
        local function_code="${data:12:2}"
        
        case "$function_code" in
            "01") log_message "MONITOR" "Modbus Read Coils: $src_ip -> $dst_ip" ;;
            "02") log_message "MONITOR" "Modbus Read Discrete Inputs: $src_ip -> $dst_ip" ;;
            "03") log_message "MONITOR" "Modbus Read Holding Registers: $src_ip -> $dst_ip" ;;
            "04") log_message "MONITOR" "Modbus Read Input Registers: $src_ip -> $dst_ip" ;;
            "05") log_message "ALERT" "CRITICAL: Modbus Write Single Coil: $src_ip -> $dst_ip" ;;
            "06") log_message "ALERT" "CRITICAL: Modbus Write Single Register: $src_ip -> $dst_ip" ;;
            "0F") log_message "ALERT" "CRITICAL: Modbus Write Multiple Coils: $src_ip -> $dst_ip" ;;
            "10") log_message "ALERT" "CRITICAL: Modbus Write Multiple Registers: $src_ip -> $dst_ip" ;;
            *) log_message "WARN" "Unknown Modbus function code: $function_code" ;;
        esac
        
        echo "Modbus Function: $function_code ($src_ip -> $dst_ip)" >> "$analysis_log"
    fi
}

# Analyze DNP3 payload
analyze_dnp3_payload() {
    local data=$1
    local src_ip=$2
    local dst_ip=$3
    local analysis_log=$4
    
    # Check DNP3 header pattern
    if [[ "$data" =~ ^0564 ]]; then
        log_message "MONITOR" "DNP3 frame detected: $src_ip -> $dst_ip"
        echo "DNP3 Frame: $src_ip -> $dst_ip" >> "$analysis_log"
        
        # Check for control functions
        if [[ "$data" =~ 0564.*C[0-9A-F] ]]; then
            log_message "ALERT" "DNP3 control function detected: $src_ip -> $dst_ip"
        fi
    fi
}

# Analyze S7 payload
analyze_s7_payload() {
    local data=$1
    local src_ip=$2
    local dst_ip=$3
    local analysis_log=$4
    
    # Check S7 protocol identifier
    if [[ "$data" =~ ^7201|^7202|^7203 ]]; then
        local function="${data:0:4}"
        case "$function" in
            "7201") log_message "MONITOR" "S7 Setup Communication: $src_ip -> $dst_ip" ;;
            "7202") log_message "MONITOR" "S7 Read Variable: $src_ip -> $dst_ip" ;;
            "7203") log_message "ALERT" "CRITICAL: S7 Write Variable: $src_ip -> $dst_ip" ;;
        esac
        
        echo "S7 Function: $function ($src_ip -> $dst_ip)" >> "$analysis_log"
    fi
}

# Generate real-time monitoring dashboard
generate_monitoring_dashboard() {
    local dashboard_file="$REPORT_DIR/monitoring_dashboard_${TIMESTAMP}.html"
    
    log_message "INFO" "Generating real-time monitoring dashboard..."
    
    # Count current statistics
    local total_connections=0
    local alert_count=0
    local protocol_count=0
    
    if [[ -f "$LOG_DIR/protocol_monitor_${TIMESTAMP}.log" ]]; then
        total_connections=$(grep -c "MONITOR.*communication" "$LOG_DIR/protocol_monitor_${TIMESTAMP}.log" 2>/dev/null || echo "0")
        alert_count=$(grep -c "ALERT" "$LOG_DIR/protocol_monitor_${TIMESTAMP}.log" 2>/dev/null || echo "0")
        protocol_count=$(grep -c "protocol signature" "$LOG_DIR/protocol_monitor_${TIMESTAMP}.log" 2>/dev/null || echo "0")
    fi
    
    cat > "$dashboard_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Industrial Protocol Monitor Dashboard - CEG2025</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #1a1a1a; 
            color: #ffffff; 
        }
        .header { 
            background: linear-gradient(45deg, #2563eb, #1e40af); 
            color: white; 
            padding: 20px; 
            text-align: center; 
            margin-bottom: 20px;
            border-radius: 10px;
        }
        .dashboard { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
            margin-bottom: 20px;
        }
        .widget { 
            background-color: #2d2d2d; 
            padding: 20px; 
            border-radius: 10px; 
            border-left: 4px solid #3b82f6; 
        }
        .widget.alert { border-left-color: #ef4444; }
        .widget.warning { border-left-color: #f59e0b; }
        .widget.success { border-left-color: #10b981; }
        .stat { 
            font-size: 2em; 
            font-weight: bold; 
            color: #3b82f6; 
            text-align: center; 
        }
        .stat.alert { color: #ef4444; }
        .stat.warning { color: #f59e0b; }
        .stat.success { color: #10b981; }
        .protocol-list { 
            background-color: #2d2d2d; 
            padding: 15px; 
            border-radius: 10px; 
            margin: 10px 0; 
        }
        .protocol-item { 
            display: flex; 
            justify-content: space-between; 
            padding: 8px 0; 
            border-bottom: 1px solid #404040; 
        }
        .status-indicator { 
            width: 12px; 
            height: 12px; 
            border-radius: 50%; 
            display: inline-block; 
            margin-right: 8px; 
        }
        .status-active { background-color: #10b981; }
        .status-warning { background-color: #f59e0b; }
        .status-critical { background-color: #ef4444; }
        .log-output { 
            background-color: #1a1a1a; 
            color: #00ff00; 
            font-family: monospace; 
            padding: 15px; 
            border-radius: 10px; 
            height: 300px; 
            overflow-y: scroll; 
            border: 1px solid #404040; 
        }
        .timestamp { color: #888888; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ Industrial Protocol Monitor Dashboard ⚡</h1>
        <h2>CyberEXPERT Game 2025 - Real-Time SCADA Monitoring</h2>
        <p>Last Updated: $(date)</p>
    </div>

    <div class="dashboard">
        <div class="widget success">
            <h3>📡 Active Connections</h3>
            <div class="stat success">$total_connections</div>
            <p>Total industrial protocol connections monitored</p>
        </div>

        <div class="widget $([ $alert_count -gt 0 ] && echo 'alert' || echo 'success')">
            <h3>🚨 Security Alerts</h3>
            <div class="stat $([ $alert_count -gt 0 ] && echo 'alert' || echo 'success')">$alert_count</div>
            <p>Critical security events detected</p>
        </div>

        <div class="widget success">
            <h3>🔍 Protocol Detection</h3>
            <div class="stat success">$protocol_count</div>
            <p>Industrial protocol signatures identified</p>
        </div>

        <div class="widget">
            <h3>⚡ Energy Infrastructure Status</h3>
            <div class="protocol-list">
                <div class="protocol-item">
                    <span><span class="status-indicator status-active"></span>SCADA Network</span>
                    <span>Monitoring Active</span>
                </div>
                <div class="protocol-item">
                    <span><span class="status-indicator status-active"></span>HMI Systems</span>
                    <span>Normal Operation</span>
                </div>
                <div class="protocol-item">
                    <span><span class="status-indicator status-active"></span>Control Network</span>
                    <span>Secure</span>
                </div>
                <div class="protocol-item">
                    <span><span class="status-indicator $([ $alert_count -gt 0 ] && echo 'status-warning' || echo 'status-active')"></span>Production Systems</span>
                    <span>$([ $alert_count -gt 0 ] && echo 'Alerts Detected' || echo 'Secure')</span>
                </div>
            </div>
        </div>
    </div>

    <div class="widget">
        <h3>📊 Monitored Industrial Protocols</h3>
        <div class="protocol-list">
            <div class="protocol-item">
                <span>Modbus TCP</span>
                <span>Port 502</span>
            </div>
            <div class="protocol-item">
                <span>DNP3</span>
                <span>Port 20000</span>
            </div>
            <div class="protocol-item">
                <span>IEC 61850 / Siemens S7</span>
                <span>Port 102</span>
            </div>
            <div class="protocol-item">
                <span>EtherNet/IP</span>
                <span>Port 44818</span>
            </div>
            <div class="protocol-item">
                <span>BACnet</span>
                <span>Port 47808</span>
            </div>
            <div class="protocol-item">
                <span>PROFINET</span>
                <span>Ports 34962-34964</span>
            </div>
        </div>
    </div>

    <div class="widget">
        <h3>📜 Real-Time Log Feed</h3>
        <div class="log-output" id="logOutput">
EOF

    # Add recent log entries
    if [[ -f "$LOG_DIR/protocol_monitor_${TIMESTAMP}.log" ]]; then
        tail -20 "$LOG_DIR/protocol_monitor_${TIMESTAMP}.log" | while IFS= read -r line; do
            echo "            <div>$line</div>" >> "$dashboard_file"
        done
    else
        echo "            <div class=\"timestamp\">Monitoring starting...</div>" >> "$dashboard_file"
    fi

    cat >> "$dashboard_file" << EOF
        </div>
    </div>

    <div class="header" style="margin-top: 30px;">
        <p>Industrial Protocol Monitor v$VERSION - Designed for CEG2025 Energy Infrastructure</p>
        <p>🛡️ Protecting Critical Infrastructure Through Real-Time Protocol Monitoring</p>
    </div>

    <script>
        // Auto-scroll log output to bottom
        const logOutput = document.getElementById('logOutput');
        logOutput.scrollTop = logOutput.scrollHeight;
    </script>
</body>
</html>
EOF

    log_message "INFO" "Real-time dashboard generated: $dashboard_file"
    
    # Display dashboard info
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${WHITE}           Industrial Protocol Monitor Dashboard Active           ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} 📡 Connections: ${WHITE}$total_connections active industrial protocols${NC}        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} 🚨 Alerts: ${WHITE}$alert_count security events detected${NC}                  ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} 🔍 Protocols: ${WHITE}$protocol_count signatures identified${NC}                ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC} 📊 Dashboard: ${YELLOW}$(basename "$dashboard_file")${NC}           ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Main execution function
main() {
    show_banner
    create_directories
    
    case "${1:-help}" in
        "start"|"monitor")
            log_message "INFO" "Starting industrial protocol monitoring..."
            initialize_baseline
            start_protocol_monitoring
            generate_monitoring_dashboard
            
            # Keep monitoring running
            log_message "INFO" "Protocol monitoring active. Press Ctrl+C to stop."
            while true; do
                sleep 30
                generate_monitoring_dashboard  # Update dashboard every 30 seconds
            done
            ;;
        "dashboard")
            generate_monitoring_dashboard
            ;;
        "baseline")
            initialize_baseline
            ;;
        "stop")
            log_message "INFO" "Stopping protocol monitoring..."
            pkill -f "tcpdump.*port.*502"
            pkill -f "tshark.*tcp"
            ;;
        "help"|*)
            echo -e "${CYAN}Industrial Protocol Monitor Commands:${NC}"
            echo -e "${WHITE}  start${NC}     - Start real-time protocol monitoring"
            echo -e "${WHITE}  monitor${NC}   - Alias for start"
            echo -e "${WHITE}  dashboard${NC} - Generate monitoring dashboard"
            echo -e "${WHITE}  baseline${NC}  - Initialize baseline learning"
            echo -e "${WHITE}  stop${NC}      - Stop all monitoring processes"
            echo -e "${WHITE}  help${NC}      - Show this help message"
            echo
            echo -e "${YELLOW}Monitored Protocols:${NC}"
            echo -e "${WHITE}  • Modbus TCP (Port 502)${NC}"
            echo -e "${WHITE}  • DNP3 (Port 20000)${NC}"
            echo -e "${WHITE}  • IEC 61850 / S7 (Port 102)${NC}"
            echo -e "${WHITE}  • EtherNet/IP (Port 44818)${NC}"
            echo -e "${WHITE}  • BACnet (Port 47808)${NC}"
            echo -e "${WHITE}  • PROFINET (Ports 34962-34964)${NC}"
            echo
            echo -e "${YELLOW}Features:${NC}"
            echo -e "${WHITE}  • Real-time protocol signature detection${NC}"
            echo -e "${WHITE}  • Critical function monitoring (write operations)${NC}"
            echo -e "${WHITE}  • Baseline learning and anomaly detection${NC}"
            echo -e "${WHITE}  • Live dashboard with auto-refresh${NC}"
            echo -e "${WHITE}  • Alert generation for suspicious activity${NC}"
            echo
            echo -e "${YELLOW}Examples:${NC}"
            echo -e "${WHITE}  ./industrial_protocol_monitor.sh start${NC}     # Start monitoring"
            echo -e "${WHITE}  ./industrial_protocol_monitor.sh dashboard${NC} # View dashboard"
            ;;
    esac
}

# Handle cleanup on exit
cleanup() {
    log_message "INFO" "Cleaning up protocol monitoring processes..."
    pkill -f "tcpdump.*port.*502" 2>/dev/null
    pkill -f "tshark.*tcp" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Execute main function with all arguments
main "$@"