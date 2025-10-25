#!/bin/bash
# CEG25 Service Availability Monitor

PHASE=$1
LOG_FILE="../logs/ceg25/service_monitor.log"

log_service() {
    echo "[$(date)] [$PHASE] $1" >> "$LOG_FILE"
}

# Monitor critical services for CEG25 scoring
monitor_services() {
    # Web services (critical for scoring)
    curl -s http://localhost >/dev/null && log_service "Web service OK" || {
        log_service "Web service DOWN - attempting restart"
        systemctl restart apache2 nginx httpd 2>/dev/null
    }
    
    # SSH access (required for management)
    systemctl is-active ssh sshd >/dev/null 2>&1 && log_service "SSH service OK" || {
        log_service "SSH service DOWN - attempting restart"
        systemctl restart ssh sshd 2>/dev/null
    }
    
    # Database services
    systemctl is-active mysql mariadb postgresql >/dev/null 2>&1 && log_service "Database services OK" || {
        log_service "Database service issues detected"
    }
}

while true; do
    monitor_services
    sleep 60
done
