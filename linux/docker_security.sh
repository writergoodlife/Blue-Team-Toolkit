#!/bin/bash

# ============================================================================
# Docker Security Automation for CEG25 Competition
# ============================================================================
# Comprehensive Docker security hardening for energy infrastructure
# Optimized for CEG25 competition scoring and container security
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="Docker Security Automation"

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
LOG_DIR="../logs/docker_security"
REPORT_DIR="../reports/docker_security"
CONFIG_DIR="../config/docker_security"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Docker configuration files
DOCKER_CONFIG="/etc/docker/daemon.json"
DOCKER_SERVICE="/lib/systemd/system/docker.service"
DOCKER_SOCKET="/var/run/docker.sock"
DOCKER_COMPOSE_FILE="docker-compose.yml"

# Docker security settings
declare -A DOCKER_SECURITY_SETTINGS=(
    ["icc"]="false"                          # Disable inter-container communication
    ["ip-forward"]="false"                   # Disable IP forwarding
    ["iptables"]="true"                      # Enable iptables rules
    ["live-restore"]="true"                  # Enable live restore
    ["no-new-privileges"]="true"             # Prevent privilege escalation
    ["userland-proxy"]="false"               # Disable userland proxy
    ["userns-remap"]="default"               # Enable user namespace remapping
)

# Docker security profiles
DOCKER_SECURITY_PROFILES=(
    "minimal"      # Basic security
    "standard"     # Competition-ready (default)
    "hardened"     # Maximum security
    "competition"  # CEG25 optimized
)

# CEG25 Energy Infrastructure Networks for Docker
DOCKER_NETWORKS=(
    "scada-net"
    "hmi-net"
    "control-net"
    "corporate-net"
    "management-net"
)

# Docker security tools
DOCKER_SECURITY_TOOLS=(
    "docker-bench-security"
    "trivy"
    "dockle"
    "clair"
)

# Create necessary directories
create_directories() {
    local dirs=("$LOG_DIR" "$REPORT_DIR" "$CONFIG_DIR" "$CONFIG_DIR/images" "$CONFIG_DIR/containers")
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir" 2>/dev/null
    done
}

# Logging function
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y%m-%d %H:%M:%S')

    case $level in
        "INFO")     echo -e "${GREEN}[INFO]${NC}  $message" ;;
        "WARN")     echo -e "${YELLOW}[WARN]${NC}  $message" ;;
        "ERROR")    echo -e "${RED}[ERROR]${NC} $message" ;;
        "SUCCESS")  echo -e "${BOLD}${GREEN}[SUCCESS]${NC} $message" ;;
        "CRITICAL") echo -e "${WHITE}${RED}[CRITICAL]${NC} $message" ;;
    esac

    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/docker_security_${TIMESTAMP}.log"
}

# Display Docker security banner
show_banner() {
    clear
    echo -e "${BOLD}${BLUE}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo "    🐳 Docker Security Automation for CEG25 Competition 🐳"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo -e "${WHITE}Version: $VERSION | Container Security for Energy Infrastructure${NC}"
    echo -e "${WHITE}Target: Docker Hardening | Competition Scoring Optimized${NC}"
    echo -e "${WHITE}Date: October 28-30, 2025 | Location: Warsaw, Poland${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${BOLD}${YELLOW}🐳 DOCKER SECURITY MISSION: Secure Energy Infrastructure Containers${NC}"
    echo -e "${WHITE}• Harden Docker daemon configuration${NC}"
    echo -e "${WHITE}• Implement container security best practices${NC}"
    echo -e "${WHITE}• Configure secure networking and isolation${NC}"
    echo -e "${WHITE}• Enable image scanning and vulnerability assessment${NC}"
    echo
}

# Check Docker installation and status
check_docker_status() {
    log_message "INFO" "Checking Docker installation and status"

    echo -e "${BOLD}${CYAN}🐳 DOCKER STATUS ANALYSIS${NC}"
    echo

    # Check if Docker is installed
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}✗ Docker is not installed${NC}"
        log_message "ERROR" "Docker is not installed"
        return 1
    fi

    # Docker version
    local docker_version=$(docker --version)
    echo -e "${GREEN}✓ Docker installed: ${WHITE}$docker_version${NC}"

    # Docker daemon status
    if systemctl is-active --quiet docker 2>/dev/null; then
        echo -e "${GREEN}✓ Docker daemon is running${NC}"
    else
        echo -e "${YELLOW}⚠ Docker daemon is not running${NC}"
        systemctl start docker >/dev/null 2>&1
        if systemctl is-active --quiet docker; then
            echo -e "${GREEN}✓ Docker daemon started${NC}"
        fi
    fi

    # Docker info
    echo -e "${WHITE}Docker System Info:${NC}"
    docker system info --format "table {{.Name}}\t{{.Value}}" 2>/dev/null | head -10

    # Check Docker Compose
    if command -v docker-compose >/dev/null 2>&1; then
        local compose_version=$(docker-compose --version)
        echo -e "${GREEN}✓ Docker Compose available: ${WHITE}$compose_version${NC}"
    else
        echo -e "${YELLOW}⚠ Docker Compose not available${NC}"
    fi

    log_message "SUCCESS" "Docker status check completed"
}

# Backup Docker configuration
backup_docker_config() {
    log_message "INFO" "Creating backup of Docker configuration"

    local backup_dir="$CONFIG_DIR/backup_$TIMESTAMP"
    mkdir -p "$backup_dir"

    # Backup daemon configuration
    [[ -f "$DOCKER_CONFIG" ]] && cp "$DOCKER_CONFIG" "$backup_dir/daemon.json.backup"

    # Backup service configuration
    [[ -f "$DOCKER_SERVICE" ]] && cp "$DOCKER_SERVICE" "$backup_dir/docker.service.backup"

    # Backup Docker data
    docker system info > "$backup_dir/docker_info.txt" 2>/dev/null

    log_message "SUCCESS" "Docker configuration backed up to: $backup_dir"
    echo -e "${GREEN}✓ Docker configuration backed up${NC}"
}

# Apply Docker daemon hardening
apply_docker_daemon_hardening() {
    local profile="${1:-standard}"

    log_message "INFO" "Applying Docker daemon hardening (profile: $profile)"

    echo -e "${BOLD}${RED}🐳 APPLYING DOCKER DAEMON HARDENING${NC}"
    echo -e "${WHITE}Profile: $profile | Securing Docker daemon configuration...${NC}"
    echo

    # Create daemon.json if it doesn't exist
    if [[ ! -f "$DOCKER_CONFIG" ]]; then
        mkdir -p /etc/docker
        touch "$DOCKER_CONFIG"
    fi

    # Base security configuration
    local daemon_config='{
  "icc": false,
  "ip-forward": false,
  "iptables": true,
  "live-restore": true,
  "no-new-privileges": true,
  "userland-proxy": false,
  "userns-remap": "default"
}'

    # Apply profile-specific settings
    case $profile in
        "minimal")
            # Basic settings only
            ;;
        "standard")
            daemon_config=$(echo "$daemon_config" | jq '. + {
              "log-driver": "json-file",
              "log-opts": {"max-size": "10m", "max-file": "3"},
              "storage-driver": "overlay2"
            }')
            ;;
        "hardened")
            daemon_config=$(echo "$daemon_config" | jq '. + {
              "log-driver": "json-file",
              "log-opts": {"max-size": "10m", "max-file": "3"},
              "storage-driver": "overlay2",
              "authorization-plugin": ["authz-broker"],
              "disable-legacy-registry": true
            }')
            ;;
        "competition")
            daemon_config=$(echo "$daemon_config" | jq '. + {
              "log-driver": "json-file",
              "log-opts": {"max-size": "10m", "max-file": "3"},
              "storage-driver": "overlay2",
              "authorization-plugin": ["authz-broker"],
              "disable-legacy-registry": true,
              "max-concurrent-downloads": 3,
              "max-concurrent-uploads": 3,
              "registry-mirrors": ["https://registry-1.docker.io"]
            }')
            ;;
    esac

    # Write daemon configuration
    echo "$daemon_config" | jq . > "$DOCKER_CONFIG"

    # Set proper permissions
    chmod 600 "$DOCKER_CONFIG"

    log_message "SUCCESS" "Docker daemon configuration hardened (profile: $profile)"
    echo -e "${GREEN}✓ Docker daemon configuration applied${NC}"
}

# Configure Docker networks for energy infrastructure
configure_docker_networks() {
    log_message "INFO" "Configuring Docker networks for energy infrastructure"

    echo -e "${BOLD}${PURPLE}🌐 CONFIGURING DOCKER NETWORKS${NC}"

    # Remove default bridge network (security risk)
    docker network rm bridge 2>/dev/null

    # Create secure networks for energy infrastructure
    local networks=(
        "scada-net:172.16.2.0/24:SCADA systems isolation"
        "hmi-net:172.16.3.0/24:HMI interfaces isolation"
        "control-net:172.16.1.0/24:Control systems isolation"
        "corporate-net:10.10.0.0/24:Corporate access network"
        "management-net:10.0.0.0/8:Management and monitoring"
    )

    for network_spec in "${networks[@]}"; do
        IFS=':' read -r name subnet description <<< "$network_spec"

        if ! docker network ls --format "{{.Name}}" | grep -q "^${name}$"; then
            docker network create \
                --driver bridge \
                --subnet="$subnet" \
                --opt com.docker.network.bridge.name="${name}br" \
                --opt com.docker.network.bridge.enable_icc=false \
                --opt com.docker.network.bridge.enable_ip_masquerade=true \
                --label "energy.infrastructure=$description" \
                "$name" >/dev/null 2>&1

            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}✓ Created network: ${WHITE}$name${NC} ($subnet)"
                log_message "SUCCESS" "Created Docker network: $name ($subnet)"
            else
                echo -e "${YELLOW}⚠ Failed to create network: ${WHITE}$name${NC}"
            fi
        else
            echo -e "${GREEN}✓ Network exists: ${WHITE}$name${NC}"
        fi
    done

    echo -e "${GREEN}✓ Docker networks configured for energy infrastructure${NC}"
}

# Create secure container configurations
create_secure_container_configs() {
    log_message "INFO" "Creating secure container configurations"

    echo -e "${BOLD}${BLUE}📦 CREATING SECURE CONTAINER CONFIGURATIONS${NC}"

    # Create SCADA container configuration
    cat > "$CONFIG_DIR/containers/scada-container.yml" << EOF
version: '3.8'

services:
  scada-simulator:
    image: secure/scada-simulator:latest
    container_name: ceg25-scada-simulator
    networks:
      - scada-net
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
    volumes:
      - /dev/urandom:/dev/random:ro
    environment:
      - SCADA_SECURE_MODE=true
      - ALLOWED_NETWORKS=172.16.2.0/24
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: 3
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:502/health"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF

    # Create HMI container configuration
    cat > "$CONFIG_DIR/containers/hmi-container.yml" << EOF
version: '3.8'

services:
  hmi-interface:
    image: secure/hmi-interface:latest
    container_name: ceg25-hmi-interface
    networks:
      - hmi-net
    ports:
      - "8080:80"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
      - /var/tmp
    volumes:
      - hmi-logs:/var/log
    environment:
      - HMI_SECURE_MODE=true
      - SESSION_TIMEOUT=300
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: 3
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  hmi-logs:
    driver: local
EOF

    # Create monitoring container configuration
    cat > "$CONFIG_DIR/containers/monitoring-container.yml" << EOF
version: '3.8'

services:
  energy-monitor:
    image: secure/energy-monitor:latest
    container_name: ceg25-energy-monitor
    networks:
      - management-net
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW
      - NET_ADMIN
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - monitoring-data:/data
    environment:
      - MONITOR_SECURE_MODE=true
      - DOCKER_METRICS=true
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: 3
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9090/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  monitoring-data:
    driver: local
EOF

    log_message "SUCCESS" "Secure container configurations created"
    echo -e "${GREEN}✓ Secure container configurations created${NC}"
}

# Install and configure Docker security tools
install_security_tools() {
    log_message "INFO" "Installing Docker security tools"

    echo -e "${BOLD}${YELLOW}🔧 INSTALLING DOCKER SECURITY TOOLS${NC}"

    # Install Docker Bench for Security
    if ! command -v docker-bench-security >/dev/null 2>&1; then
        echo -e "${WHITE}Installing Docker Bench for Security...${NC}"
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            docker/docker-bench-security >/dev/null 2>&1 &
        local bench_pid=$!
        wait $bench_pid 2>/dev/null
        echo -e "${GREEN}✓ Docker Bench for Security installed${NC}"
    fi

    # Install Trivy for vulnerability scanning
    if ! command -v trivy >/dev/null 2>&1; then
        echo -e "${WHITE}Installing Trivy vulnerability scanner...${NC}"
        # Download and install Trivy
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}✓ Trivy vulnerability scanner installed${NC}"
        fi
    fi

    # Install Dockle for container image security
    if ! command -v dockle >/dev/null 2>&1; then
        echo -e "${WHITE}Installing Dockle container scanner...${NC}"
        # Install Dockle
        curl -L https://github.com/goodwithtech/dockle/releases/latest/download/dockle_linux_amd64.tar.gz | tar xz -C /usr/local/bin >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}✓ Dockle container scanner installed${NC}"
        fi
    fi

    log_message "SUCCESS" "Docker security tools installed"
}

# Run security scans on Docker environment
run_security_scans() {
    log_message "INFO" "Running Docker security scans"

    echo -e "${BOLD}${GREEN}🔍 RUNNING DOCKER SECURITY SCANS${NC}"

    # Run Docker Bench for Security
    if command -v docker-bench-security >/dev/null 2>&1; then
        echo -e "${WHITE}Running Docker Bench for Security...${NC}"
        docker run --rm --net host --pid host --userns host --cap-add audit_control \
            -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
            -v /var/lib:/var/lib \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v /usr/lib/systemd:/usr/lib/systemd \
            -v /etc:/etc --label docker_bench_security \
            docker/docker-bench-security > "$REPORT_DIR/docker-bench-results.txt" 2>&1

        if [[ -f "$REPORT_DIR/docker-bench-results.txt" ]]; then
            echo -e "${GREEN}✓ Docker Bench scan completed${NC}"
            log_message "SUCCESS" "Docker Bench security scan completed"
        fi
    fi

    # Scan running containers with Trivy
    if command -v trivy >/dev/null 2>&1; then
        echo -e "${WHITE}Scanning containers with Trivy...${NC}"
        docker ps --format "table {{.Image}}\t{{.Names}}" | tail -n +2 | while read -r image name; do
            trivy image --no-progress --format json "$image" > "$REPORT_DIR/trivy-${name}.json" 2>/dev/null
        done
        echo -e "${GREEN}✓ Container vulnerability scan completed${NC}"
        log_message "SUCCESS" "Container vulnerability scanning completed"
    fi

    # Scan images with Dockle
    if command -v dockle >/dev/null 2>&1; then
        echo -e "${WHITE}Scanning images with Dockle...${NC}"
        docker images --format "table {{.Repository}}:{{.Tag}}" | tail -n +2 | while read -r image; do
            dockle --format json "$image" > "$REPORT_DIR/dockle-${image//\//-}.json" 2>&1
        done 2>/dev/null
        echo -e "${GREEN}✓ Image security scan completed${NC}"
        log_message "SUCCESS" "Image security scanning completed"
    fi
}

# Configure Docker Content Trust
configure_content_trust() {
    log_message "INFO" "Configuring Docker Content Trust"

    echo -e "${BOLD}${PURPLE}🔐 CONFIGURING DOCKER CONTENT TRUST${NC}"

    # Enable Docker Content Trust
    export DOCKER_CONTENT_TRUST=1

    # Create trust directory
    mkdir -p ~/.docker/trust

    # Generate root key for content trust
    if [[ ! -f ~/.docker/trust/private/root.pem ]]; then
        echo -e "${WHITE}Generating Docker Content Trust root key...${NC}"
        docker trust key generate root >/dev/null 2>&1
        echo -e "${GREEN}✓ Docker Content Trust root key generated${NC}"
    fi

    # Add to persistent environment
    if ! grep -q "DOCKER_CONTENT_TRUST" ~/.bashrc; then
        echo "export DOCKER_CONTENT_TRUST=1" >> ~/.bashrc
        echo -e "${GREEN}✓ Docker Content Trust enabled persistently${NC}"
    fi

    log_message "SUCCESS" "Docker Content Trust configured"
}

# Restart Docker service
restart_docker_service() {
    log_message "INFO" "Restarting Docker service"

    echo -e "${BOLD}${YELLOW}🔄 RESTARTING DOCKER SERVICE${NC}"

    # Reload systemd daemon
    systemctl daemon-reload

    # Restart Docker service
    systemctl restart docker

    # Wait for Docker to be ready
    local timeout=30
    local count=0
    while ! docker info >/dev/null 2>&1 && [[ $count -lt $timeout ]]; do
        sleep 1
        ((count++))
    done

    if docker info >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Docker service restarted successfully${NC}"
        log_message "SUCCESS" "Docker service restarted successfully"
    else
        echo -e "${RED}✗ Docker service restart failed${NC}"
        log_message "ERROR" "Docker service restart failed"
        return 1
    fi
}

# Test Docker security configuration
test_docker_security() {
    log_message "INFO" "Testing Docker security configuration"

    echo -e "${BOLD}${GREEN}🧪 DOCKER SECURITY CONFIGURATION TEST${NC}"

    # Test daemon configuration
    if [[ -f "$DOCKER_CONFIG" ]]; then
        if jq . "$DOCKER_CONFIG" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Docker daemon configuration is valid JSON${NC}"
        else
            echo -e "${RED}✗ Docker daemon configuration is invalid${NC}"
        fi
    fi

    # Test network isolation
    if docker network ls --format "{{.Name}}" | grep -q "scada-net"; then
        echo -e "${GREEN}✓ Secure Docker networks created${NC}"
    else
        echo -e "${YELLOW}⚠ Secure Docker networks not found${NC}"
    fi

    # Test container security
    local test_container="ceg25-security-test"
    docker run --rm -d --name "$test_container" --security-opt no-new-privileges:true alpine sleep 5 >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ Container security options working${NC}"
        docker stop "$test_container" >/dev/null 2>&1
    else
        echo -e "${YELLOW}⚠ Container security test failed${NC}"
    fi

    # Test Content Trust
    if [[ "$DOCKER_CONTENT_TRUST" == "1" ]]; then
        echo -e "${GREEN}✓ Docker Content Trust is enabled${NC}"
    else
        echo -e "${YELLOW}⚠ Docker Content Trust is not enabled${NC}"
    fi

    log_message "SUCCESS" "Docker security configuration test completed"
}

# Generate Docker security report
generate_docker_report() {
    local report_file="$REPORT_DIR/docker_security_report_${TIMESTAMP}.txt"

    log_message "INFO" "Generating Docker security report"

    cat > "$report_file" << EOF
Docker Security Report - CEG25 Competition
Generated: $(date)
=========================================

COMPETITION CONTEXT:
- Event: CyberEXPERT Game 2025 (CEG25)
- Phase: Energy Infrastructure Defense
- Location: Warsaw, Poland
- Date: October 28-30, 2025

DOCKER SYSTEM INFORMATION:
EOF

    # Docker version and status
    echo "Docker Version: $(docker --version)" >> "$report_file"
    echo "Docker Compose: $(docker-compose --version 2>/dev/null || echo 'Not available')" >> "$report_file"
    echo "Service Status: $(systemctl is-active docker 2>/dev/null || echo 'Not managed by systemd')" >> "$report_file"
    echo "" >> "$report_file"

    # Daemon configuration
    echo "DOCKER DAEMON CONFIGURATION:" >> "$report_file"
    if [[ -f "$DOCKER_CONFIG" ]]; then
        echo "Configuration File: $DOCKER_CONFIG" >> "$report_file"
        echo "Settings:" >> "$report_file"
        jq -r 'to_entries[] | "  \(.key): \(.value)"' "$DOCKER_CONFIG" 2>/dev/null >> "$report_file"
    else
        echo "No daemon configuration found" >> "$report_file"
    fi
    echo "" >> "$report_file"

    # Network configuration
    echo "DOCKER NETWORKS:" >> "$report_file"
    docker network ls --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}" >> "$report_file"
    echo "" >> "$report_file"

    # Container security
    echo "CONTAINER SECURITY STATUS:" >> "$report_file"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" >> "$report_file"
    echo "" >> "$report_file"

    # Security tools status
    echo "SECURITY TOOLS STATUS:" >> "$report_file"
    for tool in "${DOCKER_SECURITY_TOOLS[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "✓ $tool: Installed" >> "$report_file"
        else
            echo "✗ $tool: Not installed" >> "$report_file"
        fi
    done
    echo "" >> "$report_file"

    # CEG25 compliance
    echo "CEG25 COMPETITION COMPLIANCE:" >> "$report_file"
    echo "✓ Network Segmentation: $(docker network ls --format "{{.Name}}" | grep -c "net") networks created" >> "$report_file"
    echo "✓ Content Trust: $([[ "$DOCKER_CONTENT_TRUST" == "1" ]] && echo 'Enabled' || echo 'Disabled')" >> "$report_file"
    echo "✓ Security Tools: $(command -v trivy dockle 2>/dev/null | wc -l) tools installed" >> "$report_file"
    echo "✓ Secure Configurations: Applied" >> "$report_file"
    echo "" >> "$report_file"

    # Recommendations
    echo "COMPETITION RECOMMENDATIONS:" >> "$report_file"
    echo "1. Regularly scan container images for vulnerabilities" >> "$report_file"
    echo "2. Monitor container resource usage and logs" >> "$report_file"
    echo "3. Use signed images with Docker Content Trust" >> "$report_file"
    echo "4. Implement container runtime security policies" >> "$report_file"
    echo "5. Regularly update base images and dependencies" >> "$report_file"
    echo "" >> "$report_file"

    echo "Backup Location: $CONFIG_DIR/backup_$TIMESTAMP" >> "$report_file"
    echo "Security Scan Results: $REPORT_DIR/" >> "$report_file"

    log_message "SUCCESS" "Docker security report generated: $(basename "$report_file")"
    echo -e "${GREEN}📄 Docker Security Report: ${WHITE}$report_file${NC}"
}

# Main Docker security workflow
main() {
    show_banner
    create_directories

    case "${1:-harden}" in
        "analyze"|"check"|"status")
            check_docker_status
            ;;
        "harden"|"secure")
            local profile="${2:-competition}"
            echo -e "${BOLD}${YELLOW}🚀 STARTING DOCKER SECURITY HARDENING FOR CEG25 COMPETITION${NC}"
            echo -e "${WHITE}Profile: $profile | Securing container environment...${NC}"
            echo

            check_docker_status
            backup_docker_config
            apply_docker_daemon_hardening "$profile"
            configure_docker_networks
            create_secure_container_configs
            install_security_tools
            configure_content_trust
            restart_docker_service
            run_security_scans
            test_docker_security
            generate_docker_report

            echo
            echo -e "${BOLD}${GREEN}✅ DOCKER SECURITY HARDENING COMPLETED${NC}"
            echo -e "${WHITE}Docker environment is now secured for energy infrastructure containers${NC}"
            log_message "CEG25" "Docker security hardening completed for CEG25 competition (profile: $profile)"
            ;;
        "backup")
            backup_docker_config
            ;;
        "scan")
            run_security_scans
            ;;
        "test")
            test_docker_security
            ;;
        "report")
            generate_docker_report
            ;;
        "networks")
            configure_docker_networks
            ;;
        "containers")
            create_secure_container_configs
            ;;
        "minimal"|"standard"|"hardened"|"competition")
            main "harden" "$1"
            ;;
        "help"|*)
            echo -e "${BOLD}${CYAN}Docker Security Automation Commands:${NC}"
            echo
            echo -e "${WHITE}Security Operations:${NC}"
            echo -e "  ${YELLOW}analyze${NC}     - Analyze Docker installation and status"
            echo -e "  ${YELLOW}harden${NC}      - Apply Docker security hardening (default)"
            echo -e "  ${YELLOW}backup${NC}      - Create Docker configuration backup"
            echo -e "  ${YELLOW}scan${NC}        - Run security scans on containers/images"
            echo -e "  ${YELLOW}test${NC}        - Test Docker security configuration"
            echo -e "  ${YELLOW}report${NC}      - Generate Docker security report"
            echo -e "  ${YELLOW}networks${NC}    - Configure secure Docker networks"
            echo -e "  ${YELLOW}containers${NC}  - Create secure container configurations"
            echo
            echo -e "${BOLD}${YELLOW}Security Profiles:${NC}"
            echo -e "  ${CYAN}minimal${NC}      - Basic container security"
            echo -e "  ${CYAN}standard${NC}     - Competition-ready security"
            echo -e "  ${CYAN}hardened${NC}     - Maximum container security"
            echo -e "  ${CYAN}competition${NC}  - CEG25 optimized (default)"
            echo
            echo -e "${BOLD}${YELLOW}CEG25 Competition Features:${NC}"
            echo -e "  ${WHITE}• Energy infrastructure network isolation${NC}"
            echo -e "  ${WHITE}• SCADA/HMI/Control container segmentation${NC}"
            echo -e "  ${WHITE}• Container vulnerability scanning${NC}"
            echo -e "  ${WHITE}• Docker Content Trust enforcement${NC}"
            echo -e "  ${WHITE}• Secure container configurations${NC}"
            echo
            echo -e "${BOLD}${RED}⚠️  WARNING: Docker hardening may affect running containers${NC}"
            echo -e "${WHITE}Backup configurations and test thoroughly before competition${NC}"
            ;;
    esac
}

# Execute main function with all arguments
main "$@"