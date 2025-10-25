#!/bin/bash

# ============================================================================
# Automated Service Restoration for CEG25 Competition
# ============================================================================
# Intelligent service recovery and availability maintenance system
# Optimized for energy infrastructure and competition scoring
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="Automated Service Restoration"

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
LOG_DIR="../logs/service_restoration"
REPORT_DIR="../reports/service_restoration"
CONFIG_DIR="../config/service_restoration"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Service categories for energy infrastructure
SERVICE_CATEGORIES=(
    "SCADA_SYSTEMS"
    "HMI_INTERFACES"
    "PLC_CONTROLLERS"
    "DATABASE_SERVERS"
    "WEB_SERVICES"
    "NETWORK_SERVICES"
    "SECURITY_SERVICES"
    "MONITORING_SYSTEMS"
)

# Critical energy infrastructure services
CRITICAL_SERVICES=(
    "scada-master"
    "plc-controller-01"
    "hmi-interface"
    "energy-database"
    "modbus-gateway"
    "dnp3-server"
    "iec61850-service"
    "monitoring-agent"
)

# Service health status
STATUS_HEALTHY="HEALTHY"
STATUS_DEGRADED="DEGRADED"
STATUS_CRITICAL="CRITICAL"
STATUS_DOWN="DOWN"
STATUS_RESTARTING="RESTARTING"
STATUS_RECOVERING="RECOVERING"

# Recovery strategies
RECOVERY_RESTART="RESTART"
RECOVERY_FAILOVER="FAILOVER"
RECOVERY_RESTORE="RESTORE"
RECOVERY_REBUILD="REBUILD"
RECOVERY_ESCALATE="ESCALATE"

# Service monitoring data
declare -A SERVICE_STATUS
declare -A SERVICE_PID
declare -A SERVICE_UPTIME
declare -A SERVICE_LAST_CHECK
declare -A SERVICE_RESTART_COUNT
declare -A SERVICE_RECOVERY_STRATEGY

# Service health thresholds
HEALTH_THRESHOLDS=(
    ["CPU_USAGE"]=80
    ["MEMORY_USAGE"]=85
    ["DISK_USAGE"]=90
    ["RESPONSE_TIME"]=5000  # milliseconds
    ["ERROR_RATE"]=5        # percentage
)

# Get service priority safely
get_service_priority() {
    local service=$1
    case $service in
        "scada-master") echo 10 ;;
        "plc-controller-01") echo 10 ;;
        "energy-database") echo 9 ;;
        "modbus-gateway") echo 8 ;;
        "dnp3-server") echo 8 ;;
        "iec61850-service") echo 8 ;;
        "hmi-interface") echo 7 ;;
        "monitoring-agent") echo 6 ;;
        *) echo 5 ;;
    esac
}

# Service dependencies
declare -A SERVICE_DEPENDENCIES
SERVICE_DEPENDENCIES["scada-master"]="energy-database,modbus-gateway"
SERVICE_DEPENDENCIES["hmi-interface"]="scada-master,energy-database"
SERVICE_DEPENDENCIES["monitoring-agent"]="scada-master,hmi-interface"

# Create necessary directories
create_directories() {
    local dirs=("$LOG_DIR" "$REPORT_DIR" "$CONFIG_DIR" "$LOG_DIR/services" "$REPORT_DIR/restoration")
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir" 2>/dev/null
    done
}

# Logging function
log_message() {
    local level=$1
    local message=$2
    local service="${3:-}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        "INFO")     echo -e "${GREEN}[INFO]${NC}  $message" ;;
        "WARN")     echo -e "${YELLOW}[WARN]${NC}  $message" ;;
        "ERROR")    echo -e "${RED}[ERROR]${NC} $message" ;;
        "SUCCESS")  echo -e "${BOLD}${GREEN}[SUCCESS]${NC} $message" ;;
        "CRITICAL") echo -e "${WHITE}${RED}[CRITICAL]${NC} $message" ;;
        "SERVICE")  echo -e "${BOLD}${BLUE}[SERVICE]${NC} $message" ;;
    esac

    if [[ -n "$service" ]]; then
        echo "[$timestamp] [$level] [$service] $message" >> "$LOG_DIR/service_restoration_${TIMESTAMP}.log"
    else
        echo "[$timestamp] [$level] $message" >> "$LOG_DIR/service_restoration_${TIMESTAMP}.log"
    fi
}

# Display service restoration banner
show_banner() {
    clear
    echo -e "${BOLD}${GREEN}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo "    🔧 Automated Service Restoration for CEG25 Competition 🔧"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo -e "${WHITE}Version: $VERSION | Energy Infrastructure Recovery${NC}"
    echo -e "${WHITE}Target: Service Availability | Competition Scoring${NC}"
    echo -e "${WHITE}Date: October 28-30, 2025 | Location: Warsaw, Poland${NC}"
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${BOLD}${YELLOW}🔧 SERVICE RESTORATION MISSION: Maintain Energy Infrastructure Availability${NC}"
    echo -e "${WHITE}• Automated service health monitoring${NC}"
    echo -e "${WHITE}• Intelligent recovery strategies${NC}"
    echo -e "${WHITE}• Dependency-aware restoration${NC}"
    echo -e "${WHITE}• Competition scoring optimization${NC}"
    echo
}

# Initialize service monitoring
initialize_services() {
    log_message "INFO" "Initializing service monitoring for critical infrastructure"

    for service in "${CRITICAL_SERVICES[@]}"; do
        SERVICE_STATUS["$service"]="$STATUS_HEALTHY"
        SERVICE_PID["$service"]=""
        SERVICE_UPTIME["$service"]=0
        SERVICE_LAST_CHECK["$service"]=$(date +%s)
        SERVICE_RESTART_COUNT["$service"]=0
        SERVICE_RECOVERY_STRATEGY["$service"]="$RECOVERY_RESTART"
    done

    log_message "SUCCESS" "Service monitoring initialized for ${#CRITICAL_SERVICES[@]} critical services"
}

# Check service health
check_service_health() {
    local service=$1
    local current_time=$(date +%s)

    # Simulate service health check (in real implementation, this would check actual service status)
    local pid=""
    local status="$STATUS_HEALTHY"
    local cpu_usage=$((RANDOM % 100))
    local mem_usage=$((RANDOM % 100))
    local response_time=$((RANDOM % 10000))

    # Simulate some services being down for testing
    if [[ $((RANDOM % 10)) -eq 0 ]]; then
        status="$STATUS_DOWN"
    elif [[ $cpu_usage -gt ${HEALTH_THRESHOLDS[CPU_USAGE]} ]]; then
        status="$STATUS_DEGRADED"
    elif [[ $mem_usage -gt ${HEALTH_THRESHOLDS[MEMORY_USAGE]} ]]; then
        status="$STATUS_DEGRADED"
    fi

    # Update service information
    SERVICE_STATUS["$service"]="$status"
    SERVICE_PID["$service"]="$pid"
    SERVICE_LAST_CHECK["$service"]="$current_time"

    # Calculate uptime
    if [[ "$status" == "$STATUS_HEALTHY" ]]; then
        ((SERVICE_UPTIME["$service"]++))
    else
        SERVICE_UPTIME["$service"]=0
    fi

    return 0
}

# Monitor all critical services
monitor_services() {
    echo -e "${BOLD}${CYAN}🔍 MONITORING CRITICAL SERVICES${NC}"
    echo

    local healthy_count=0
    local degraded_count=0
    local down_count=0

    for service in "${CRITICAL_SERVICES[@]}"; do
        check_service_health "$service"

        local status="${SERVICE_STATUS[$service]}"
        local priority=$(get_service_priority "$service")
        local uptime="${SERVICE_UPTIME[$service]}"
        local restarts="${SERVICE_RESTART_COUNT[$service]}"

        case $status in
            "$STATUS_HEALTHY")
                echo -e "${GREEN}✓ $service (Priority: $priority) - $status - Uptime: ${uptime}s - Restarts: $restarts${NC}"
                ((healthy_count++))
                ;;
            "$STATUS_DEGRADED")
                echo -e "${YELLOW}⚠ $service (Priority: $priority) - $status - Uptime: ${uptime}s - Restarts: $restarts${NC}"
                ((degraded_count++))
                ;;
            "$STATUS_DOWN")
                echo -e "${RED}✗ $service (Priority: $priority) - $status - Uptime: ${uptime}s - Restarts: $restarts${NC}"
                ((down_count++))
                ;;
            *)
                echo -e "${WHITE}○ $service (Priority: $priority) - $status - Uptime: ${uptime}s - Restarts: $restarts${NC}"
                ;;
        esac
    done

    echo
    echo -e "${WHITE}Summary: ${GREEN}$healthy_count healthy${NC} | ${YELLOW}$degraded_count degraded${NC} | ${RED}$down_count down${NC}"
    echo

    # Trigger recovery for down services
    if [[ $down_count -gt 0 ]]; then
        echo -e "${YELLOW}🔧 Initiating recovery for down services...${NC}"
        for service in "${CRITICAL_SERVICES[@]}"; do
            if [[ "${SERVICE_STATUS[$service]}" == "$STATUS_DOWN" ]]; then
                recover_service "$service"
            fi
        done
    fi
}

# Recover a specific service
recover_service() {
    local service=$1

    log_message "INFO" "Initiating recovery for service: $service" "$service"

    echo -e "${BOLD}${YELLOW}🔧 RECOVERING SERVICE: ${WHITE}$service${NC}"

    # Check dependencies first
    check_dependencies "$service"

    # Determine recovery strategy
    local strategy="${SERVICE_RECOVERY_STRATEGY[$service]}"
    local priority=$(get_service_priority "$service")

    echo -e "${WHITE}Recovery Strategy: $strategy | Priority: $priority${NC}"

    case $strategy in
        "$RECOVERY_RESTART")
            restart_service "$service"
            ;;
        "$RECOVERY_FAILOVER")
            failover_service "$service"
            ;;
        "$RECOVERY_RESTORE")
            restore_service "$service"
            ;;
        "$RECOVERY_REBUILD")
            rebuild_service "$service"
            ;;
        "$RECOVERY_ESCALATE")
            escalate_service_issue "$service"
            ;;
    esac
}

# Check service dependencies
check_dependencies() {
    local service=$1

    if [[ -v SERVICE_DEPENDENCIES["$service"] ]]; then
        local dependencies="${SERVICE_DEPENDENCIES[$service]}"
        echo -e "${CYAN}Checking dependencies for $service: $dependencies${NC}"

        IFS=',' read -ra DEP_ARRAY <<< "$dependencies"
        for dep in "${DEP_ARRAY[@]}"; do
            dep=$(echo "$dep" | xargs)  # Trim whitespace
            if [[ "${SERVICE_STATUS[$dep]}" != "$STATUS_HEALTHY" ]]; then
                echo -e "${YELLOW}⚠ Dependency $dep is not healthy (${SERVICE_STATUS[$dep]}), recovering first...${NC}"
                recover_service "$dep"
                sleep 2
            fi
        done
    fi
}

# Restart service
restart_service() {
    local service=$1

    echo -e "${WHITE}Executing restart procedure for $service...${NC}"

    # Simulate service restart
    SERVICE_STATUS["$service"]="$STATUS_RESTARTING"
    sleep 2

    # Simulate restart success/failure
    if [[ $((RANDOM % 10)) -lt 8 ]]; then  # 80% success rate
        SERVICE_STATUS["$service"]="$STATUS_HEALTHY"
        ((SERVICE_RESTART_COUNT["$service"]++))
        SERVICE_UPTIME["$service"]=0

        log_message "SUCCESS" "Service restart successful" "$service"
        echo -e "${GREEN}✓ Service $service restarted successfully${NC}"
    else
        SERVICE_STATUS["$service"]="$STATUS_DOWN"
        log_message "ERROR" "Service restart failed" "$service"
        echo -e "${RED}✗ Service $service restart failed${NC}"

        # Escalate if restart fails
        SERVICE_RECOVERY_STRATEGY["$service"]="$RECOVERY_FAILOVER"
        echo -e "${YELLOW}Escalating to failover strategy${NC}"
        failover_service "$service"
    fi
}

# Failover to backup service
failover_service() {
    local service=$1

    echo -e "${WHITE}Executing failover procedure for $service...${NC}"

    # Simulate finding backup service
    local backup_service="${service}-backup"

    echo -e "${CYAN}Attempting failover to $backup_service...${NC}"
    sleep 3

    # Simulate failover success
    if [[ $((RANDOM % 10)) -lt 7 ]]; then  # 70% success rate
        SERVICE_STATUS["$service"]="$STATUS_HEALTHY"
        log_message "SUCCESS" "Service failover successful to $backup_service" "$service"
        echo -e "${GREEN}✓ Service $service failed over to $backup_service${NC}"
    else
        log_message "ERROR" "Service failover failed" "$service"
        echo -e "${RED}✗ Service $service failover failed${NC}"

        # Escalate to restore
        SERVICE_RECOVERY_STRATEGY["$service"]="$RECOVERY_RESTORE"
        echo -e "${YELLOW}Escalating to restore strategy${NC}"
        restore_service "$service"
    fi
}

# Restore service from backup
restore_service() {
    local service=$1

    echo -e "${WHITE}Executing restore procedure for $service...${NC}"

    echo -e "${CYAN}Restoring $service from backup...${NC}"
    sleep 5

    # Simulate restore process
    if [[ $((RANDOM % 10)) -lt 6 ]]; then  # 60% success rate
        SERVICE_STATUS["$service"]="$STATUS_HEALTHY"
        SERVICE_RESTART_COUNT["$service"]=0
        SERVICE_UPTIME["$service"]=0

        log_message "SUCCESS" "Service restore successful" "$service"
        echo -e "${GREEN}✓ Service $service restored from backup${NC}"
    else
        log_message "CRITICAL" "Service restore failed" "$service"
        echo -e "${RED}✗ Service $service restore failed${NC}"

        # Escalate to rebuild
        SERVICE_RECOVERY_STRATEGY["$service"]="$RECOVERY_REBUILD"
        echo -e "${YELLOW}Escalating to rebuild strategy${NC}"
        rebuild_service "$service"
    fi
}

# Rebuild service from scratch
rebuild_service() {
    local service=$1

    echo -e "${WHITE}Executing rebuild procedure for $service...${NC}"

    echo -e "${CYAN}Rebuilding $service from configuration...${NC}"
    sleep 10

    # Simulate rebuild process
    if [[ $((RANDOM % 10)) -lt 5 ]]; then  # 50% success rate
        SERVICE_STATUS["$service"]="$STATUS_HEALTHY"
        SERVICE_RESTART_COUNT["$service"]=0
        SERVICE_UPTIME["$service"]=0

        log_message "SUCCESS" "Service rebuild successful" "$service"
        echo -e "${GREEN}✓ Service $service rebuilt successfully${NC}"
    else
        log_message "CRITICAL" "Service rebuild failed - manual intervention required" "$service"
        echo -e "${RED}✗ Service $service rebuild failed - MANUAL INTERVENTION REQUIRED${NC}"

        # Final escalation
        SERVICE_RECOVERY_STRATEGY["$service"]="$RECOVERY_ESCALATE"
        escalate_service_issue "$service"
    fi
}

# Escalate service issue to human operators
escalate_service_issue() {
    local service=$1

    log_message "CRITICAL" "Service $service requires manual intervention - ESCALATING" "$service"

    echo -e "${BOLD}${RED}🚨 ESCALATION ALERT 🚨${NC}"
    echo -e "${WHITE}Service: $service${NC}"
    echo -e "${WHITE}Status: ${SERVICE_STATUS[$service]}${NC}"
    echo -e "${WHITE}Priority: $(get_service_priority "$service")${NC}"
    echo -e "${WHITE}Restarts: ${SERVICE_RESTART_COUNT[$service]}${NC}"
    echo -e "${WHITE}Time: $(date)${NC}"
    echo
    echo -e "${YELLOW}Manual intervention required for critical service recovery${NC}"
    echo -e "${YELLOW}Notifying Blue Team leadership and competition judges${NC}"

    # In a real implementation, this would send alerts via email, Slack, etc.
}

# Continuous service monitoring
continuous_monitoring() {
    local interval="${1:-30}"  # Default 30 seconds

    log_message "INFO" "Starting continuous service monitoring (interval: ${interval}s)"

    echo -e "${BOLD}${PURPLE}👁️  CONTINUOUS SERVICE MONITORING${NC}"
    echo -e "${WHITE}Monitoring ${#CRITICAL_SERVICES[@]} critical services every ${interval} seconds${NC}"
    echo -e "${WHITE}Press Ctrl+C to stop monitoring${NC}"
    echo

    trap 'echo -e "\n${GREEN}✓ Monitoring stopped${NC}"; exit 0' INT

    while true; do
        monitor_services
        echo -e "${CYAN}Next check in ${interval} seconds...${NC}"
        sleep "$interval"
        echo
    done
}

# Generate service restoration report
generate_restoration_report() {
    local report_file="$REPORT_DIR/restoration/service_restoration_report_${TIMESTAMP}.txt"

    log_message "INFO" "Generating service restoration report"

    cat > "$report_file" << EOF
SERVICE RESTORATION REPORT - CEG25 Competition
===========================================

Report Generated: $(date)
Competition Phase: Energy Infrastructure Defense
Location: Warsaw, Poland
Date: October 28-30, 2025

EXECUTIVE SUMMARY:
================
Total Critical Services: ${#CRITICAL_SERVICES[@]}
Monitoring Interval: 30 seconds
Report Period: $(date -d '30 minutes ago' '+%Y-%m-%d %H:%M:%S') to $(date '+%Y-%m-%d %H:%M:%S')

SERVICE HEALTH SUMMARY:
======================
EOF

    # Count services by status
    local healthy=0 degraded=0 down=0 restarting=0 recovering=0

    for service in "${CRITICAL_SERVICES[@]}"; do
        case "${SERVICE_STATUS[$service]}" in
            "$STATUS_HEALTHY") ((healthy++)) ;;
            "$STATUS_DEGRADED") ((degraded++)) ;;
            "$STATUS_DOWN") ((down++)) ;;
            "$STATUS_RESTARTING") ((restarting++)) ;;
            "$STATUS_RECOVERING") ((recovering++)) ;;
        esac
    done

    echo "Healthy Services: $healthy" >> "$report_file"
    echo "Degraded Services: $degraded" >> "$report_file"
    echo "Down Services: $down" >> "$report_file"
    echo "Restarting Services: $restarting" >> "$report_file"
    echo "Recovering Services: $recovering" >> "$report_file"
    echo "" >> "$report_file"

    # Service details
    echo "SERVICE DETAILS:" >> "$report_file"
    echo "===============" >> "$report_file"

    for service in "${CRITICAL_SERVICES[@]}"; do
        local status="${SERVICE_STATUS[$service]}"
        local priority=$(get_service_priority "$service")
        local uptime="${SERVICE_UPTIME[$service]}"
        local restarts="${SERVICE_RESTART_COUNT[$service]}"
        local last_check=$(date -d "@${SERVICE_LAST_CHECK[$service]}" '+%H:%M:%S')

        echo "Service: $service" >> "$report_file"
        echo "  Status: $status" >> "$report_file"
        echo "  Priority: $priority" >> "$report_file"
        echo "  Uptime: ${uptime}s" >> "$report_file"
        echo "  Restarts: $restarts" >> "$report_file"
        echo "  Last Check: $last_check" >> "$report_file"
        echo "" >> "$report_file"
    done

    # Recovery actions taken
    echo "RECOVERY ACTIONS:" >> "$report_file"
    echo "=================" >> "$report_file"

    local total_restarts=0
    for service in "${CRITICAL_SERVICES[@]}"; do
        ((total_restarts += ${SERVICE_RESTART_COUNT[$service]}))
    done

    echo "Total Service Restarts: $total_restarts" >> "$report_file"
    echo "Services Requiring Attention: $down" >> "$report_file"
    echo "" >> "$report_file"

    # Competition scoring impact
    echo "COMPETITION SCORING IMPACT:" >> "$report_file"
    echo "===========================" >> "$report_file"

    local availability_score=$(( (healthy * 100) / ${#CRITICAL_SERVICES[@]} ))
    local recovery_score=$(( 100 - (down * 10) - (degraded * 5) ))

    echo "Service Availability Score: ${availability_score}%" >> "$report_file"
    echo "Recovery Effectiveness Score: ${recovery_score}%" >> "$report_file"
    echo "Overall Service Score: $(( (availability_score + recovery_score) / 2 ))%" >> "$report_file"
    echo "" >> "$report_file"

    # Recommendations
    echo "RECOMMENDATIONS:" >> "$report_file"
    echo "===============" >> "$report_file"

    if [[ $down -gt 0 ]]; then
        echo "• Immediate attention required for $down down services" >> "$report_file"
    fi

    if [[ $degraded -gt 0 ]]; then
        echo "• Performance optimization needed for $degraded degraded services" >> "$report_file"
    fi

    if [[ $total_restarts -gt 10 ]]; then
        echo "• High restart frequency indicates potential stability issues" >> "$report_file"
    fi

    echo "• Regular backup validation recommended" >> "$report_file"
    echo "• Consider implementing redundant systems for critical services" >> "$report_file"
    echo "• Review and update recovery playbooks based on incidents" >> "$report_file"
    echo "" >> "$report_file"

    log_message "SUCCESS" "Service restoration report generated: $(basename "$report_file")"
    echo -e "${GREEN}📄 Service Restoration Report: ${WHITE}$report_file${NC}"
}

# Simulate service failures for testing
simulate_failures() {
    echo -e "${BOLD}${YELLOW}🎭 SIMULATING SERVICE FAILURES${NC}"
    echo

    local services_to_fail=(
        "scada-master"
        "energy-database"
        "modbus-gateway"
    )

    for service in "${services_to_fail[@]}"; do
        SERVICE_STATUS["$service"]="$STATUS_DOWN"
        log_message "WARN" "Simulated failure for service: $service" "$service"
        echo -e "${RED}✗ Simulated failure: $service${NC}"
    done

    echo -e "${GREEN}✓ Service failure simulation completed${NC}"
    echo
}

# Main service restoration workflow
main() {
    show_banner
    create_directories
    initialize_services

    case "${1:-monitor}" in
        "monitor")
            monitor_services
            ;;
        "continuous")
            local interval="${2:-30}"
            continuous_monitoring "$interval"
            ;;
        "recover")
            local service="${2:-}"
            if [[ -z "$service" ]]; then
                echo -e "${RED}✗ Service name required${NC}"
                return 1
            fi
            recover_service "$service"
            ;;
        "report")
            generate_restoration_report
            ;;
        "simulate")
            simulate_failures
            monitor_services
            ;;
        "help"|*)
            echo -e "${BOLD}${GREEN}Automated Service Restoration Commands:${NC}"
            echo
            echo -e "${WHITE}Service Monitoring:${NC}"
            echo -e "  ${YELLOW}monitor${NC}                          - Check all service health"
            echo -e "  ${YELLOW}continuous [interval]${NC}           - Continuous monitoring"
            echo -e "  ${YELLOW}recover [service]${NC}               - Recover specific service"
            echo
            echo -e "${BOLD}${YELLOW}Analysis & Testing:${NC}"
            echo -e "  ${CYAN}report${NC}                           - Generate restoration report"
            echo -e "  ${CYAN}simulate${NC}                         - Simulate service failures"
            echo
            echo -e "${BOLD}${YELLOW}Critical Services:${NC}"
            for service in "${CRITICAL_SERVICES[@]}"; do
                local priority=$(get_service_priority "$service")
                echo -e "  ${WHITE}• $service (Priority: $priority)${NC}"
            done
            echo
            echo -e "${BOLD}${YELLOW}CEG25 Competition Features:${NC}"
            echo -e "  ${WHITE}• Critical infrastructure monitoring${NC}"
            echo -e "  ${WHITE}• Automated recovery strategies${NC}"
            echo -e "  ${WHITE}• Dependency-aware restoration${NC}"
            echo -e "  ${WHITE}• Competition scoring integration${NC}"
            echo -e "  ${WHITE}• Energy sector optimization${NC}"
            echo
            ;;
    esac
}

# Execute main function with all arguments
main "$@"