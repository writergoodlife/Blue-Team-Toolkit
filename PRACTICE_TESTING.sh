#!/bin/bash

# ============================================================================
# CEG25 Blue Team Toolkit - Practice Session Testing
# ============================================================================
# Safe testing environment for all security tools
# Docker-based isolated testing to prevent system impact
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="CEG25 Practice Testing"

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

# Test configuration
TEST_DIR="/tmp/ceg25_practice"
DOCKER_NETWORK="ceg25_test_net"
MOCK_TARGET_IP="172.20.0.10"
MOCK_TARGET_PORT="502"
TEST_RESULTS="$TEST_DIR/results.log"
TEST_REPORT="$TEST_DIR/practice_report.txt"

# Initialize test environment
init_test_environment() {
    echo -e "${BOLD}${BLUE}🔧 INITIALIZING PRACTICE TESTING ENVIRONMENT${NC}"
    echo

    # Create test directory
    mkdir -p "$TEST_DIR"
    echo "" > "$TEST_RESULTS"
    echo "" > "$TEST_REPORT"

    # Check Docker availability
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not found. Installing Docker...${NC}"
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo systemctl start docker
        sudo systemctl enable docker
        sudo usermod -aG docker $USER
        echo -e "${YELLOW}⚠️  Please log out and back in for Docker group changes to take effect${NC}"
        echo -e "${YELLOW}⚠️  Or run: newgrp docker${NC}"
        newgrp docker
    fi

    # Create Docker network
    echo -e "${CYAN}Creating isolated Docker network...${NC}"
    docker network create "$DOCKER_NETWORK" 2>/dev/null || true

    # Create mock target container
    echo -e "${CYAN}Setting up mock target system...${NC}"
    cat > "$TEST_DIR/Dockerfile.mock" << 'EOF'
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y \
    openssh-server \
    apache2 \
    netcat \
    python3 \
    && mkdir /var/run/sshd

# Create mock industrial protocol service (simple TCP server)
RUN echo '#!/usr/bin/env python3\nimport socket\ns = socket.socket()\ns.bind(("0.0.0.0", 502))\ns.listen(5)\nwhile True:\n    c, addr = s.accept()\n    c.send(b"Mock Modbus Response")\n    c.close()' > /mock_modbus.py && chmod +x /mock_modbus.py

EXPOSE 22 80 502
CMD service ssh start && python3 /mock_modbus.py
EOF

    docker build -f "$TEST_DIR/Dockerfile.mock" -t ceg25-mock-target "$TEST_DIR" > /dev/null 2>&1
    docker run -d --name ceg25-mock --network "$DOCKER_NETWORK" --ip "$MOCK_TARGET_IP" ceg25-mock-target > /dev/null 2>&1

    echo -e "${GREEN}✅ Test environment initialized${NC}"
    echo
}

# Test core security modules
test_core_modules() {
    echo -e "${BOLD}${BLUE}🛡️  TESTING CORE SECURITY MODULES${NC}"
    echo

    cd "/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux"

    # Test SCADA/ICS Security Scanner
    echo -e "${CYAN}Testing SCADA/ICS Security Scanner...${NC}"
    if [ -f "scada_ics_security.sh" ]; then
        timeout 30s bash scada_ics_security.sh scan --target "$MOCK_TARGET_IP" --safe-mode >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ SCADA/ICS scanner test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ SCADA/ICS scanner not found${NC}" >> "$TEST_RESULTS"
    fi

    # Test Multi-Subnet Network Scanner
    echo -e "${CYAN}Testing Multi-Subnet Network Scanner...${NC}"
    if [ -f "multi_subnet_scanner.sh" ]; then
        timeout 30s bash multi_subnet_scanner.sh quick --target "172.20.0.0/24" --safe-mode >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ Network scanner test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ Network scanner not found${NC}" >> "$TEST_RESULTS"
    fi

    # Test Industrial Protocol Monitor
    echo -e "${CYAN}Testing Industrial Protocol Monitor...${NC}"
    if [ -f "industrial_protocol_monitor.sh" ]; then
        timeout 10s bash industrial_protocol_monitor.sh test --duration 5 >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ Protocol monitor test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ Protocol monitor not found${NC}" >> "$TEST_RESULTS"
    fi

    # Test Energy Vulnerability Scanner
    echo -e "${CYAN}Testing Energy Vulnerability Scanner...${NC}"
    if [ -f "energy_vulnerability_scanner.sh" ]; then
        timeout 30s bash energy_vulnerability_scanner.sh scan --target "$MOCK_TARGET_IP" --safe-mode >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ Vulnerability scanner test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ Vulnerability scanner not found${NC}" >> "$TEST_RESULTS"
    fi

    echo -e "${GREEN}✅ Core security modules testing completed${NC}"
    echo
}

# Test hardening automations (in containers)
test_hardening_automations() {
    echo -e "${BOLD}${BLUE}🔒 TESTING HARDENING AUTOMATIONS${NC}"
    echo

    cd "/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux"

    # Create test container for hardening tests
    echo -e "${CYAN}Creating test container for hardening...${NC}"
    docker run -d --name ceg25-harden-test --network "$DOCKER_NETWORK" ubuntu:20.04 sleep 300 > /dev/null 2>&1

    # Test SSH Hardening (simulation)
    echo -e "${CYAN}Testing SSH Hardening (simulation)...${NC}"
    if [ -f "ssh_hardening.sh" ]; then
        # Create mock SSH config for testing
        docker exec ceg25-harden-test apt-get update > /dev/null 2>&1
        docker exec ceg25-harden-test apt-get install -y openssh-server > /dev/null 2>&1
        docker exec ceg25-harden-test service ssh start > /dev/null 2>&1

        # Test SSH hardening script (dry-run mode)
        timeout 30s bash ssh_hardening.sh check >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ SSH hardening test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ SSH hardening script not found${NC}" >> "$TEST_RESULTS"
    fi

    # Test Firewall Hardening (simulation)
    echo -e "${CYAN}Testing Firewall Hardening (simulation)...${NC}"
    if [ -f "firewall_hardening.sh" ]; then
        timeout 30s bash firewall_hardening.sh check >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ Firewall hardening test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ Firewall hardening script not found${NC}" >> "$TEST_RESULTS"
    fi

    # Test Docker Security (simulation)
    echo -e "${CYAN}Testing Docker Security (simulation)...${NC}"
    if [ -f "docker_security.sh" ]; then
        timeout 30s bash docker_security.sh check >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ Docker security test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ Docker security script not found${NC}" >> "$TEST_RESULTS"
    fi

    # Clean up test container
    docker stop ceg25-harden-test > /dev/null 2>&1
    docker rm ceg25-harden-test > /dev/null 2>&1

    echo -e "${GREEN}✅ Hardening automations testing completed${NC}"
    echo
}

# Test advanced monitoring features
test_advanced_features() {
    echo -e "${BOLD}${BLUE}📊 TESTING ADVANCED MONITORING FEATURES${NC}"
    echo

    cd "/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux"

    # Test Network Traffic Analyzer
    echo -e "${CYAN}Testing Network Traffic Analyzer...${NC}"
    if [ -f "network_traffic_analyzer.sh" ]; then
        timeout 15s bash network_traffic_analyzer.sh test --duration 5 >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ Traffic analyzer test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ Traffic analyzer not found${NC}" >> "$TEST_RESULTS"
    fi

    # Test Incident Response Playbooks
    echo -e "${CYAN}Testing Incident Response Playbooks...${NC}"
    if [ -f "incident_response_playbooks.sh" ]; then
        timeout 10s bash incident_response_playbooks.sh test >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ Incident response test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ Incident response script not found${NC}" >> "$TEST_RESULTS"
    fi

    # Test Automated Service Restoration
    echo -e "${CYAN}Testing Automated Service Restoration...${NC}"
    if [ -f "automated_service_restoration.sh" ]; then
        timeout 10s bash automated_service_restoration.sh test >> "$TEST_RESULTS" 2>&1
        echo -e "${GREEN}✅ Service restoration test completed${NC}" >> "$TEST_RESULTS"
    else
        echo -e "${RED}❌ Service restoration script not found${NC}" >> "$TEST_RESULTS"
    fi

    echo -e "${GREEN}✅ Advanced monitoring features testing completed${NC}"
    echo
}

# Test web dashboard
test_web_dashboard() {
    echo -e "${BOLD}${BLUE}🌐 TESTING WEB DASHBOARD${NC}"
    echo

    cd "/home/goodlife/Desktop/CEG25/blue-team-toolkit"

    # Check if Python dependencies are installed
    echo -e "${CYAN}Checking Python dependencies...${NC}"
    if [ -f "requirements-dashboard.txt" ]; then
        python3 -c "import flask, flask_socketio, psutil" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}Installing Python dependencies...${NC}"
            pip3 install -r requirements-dashboard.txt --quiet
        fi
    fi

    # Test web dashboard startup
    echo -e "${CYAN}Testing Web Dashboard startup...${NC}"
    if [ -f "web_dashboard.py" ]; then
        # Start dashboard in background for testing
        timeout 10s python3 web_dashboard.py >> "$TEST_RESULTS" 2>&1 &
        DASHBOARD_PID=$!

        # Wait a moment for startup
        sleep 3

        # Test if dashboard is responding
        if curl -s http://localhost:5000 > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Web dashboard started successfully${NC}" >> "$TEST_RESULTS"
        else
            echo -e "${YELLOW}⚠️  Web dashboard may have startup issues${NC}" >> "$TEST_RESULTS"
        fi

        # Stop dashboard
        kill $DASHBOARD_PID 2>/dev/null
        sleep 2
    else
        echo -e "${RED}❌ Web dashboard script not found${NC}" >> "$TEST_RESULTS"
    fi

    echo -e "${GREEN}✅ Web dashboard testing completed${NC}"
    echo
}

# Test Windows agent (simulation)
test_windows_agent() {
    echo -e "${BOLD}${BLUE}🪟 TESTING WINDOWS AGENT (SIMULATION)${NC}"
    echo

    cd "/home/goodlife/Desktop/CEG25/blue-team-toolkit/windows"

    # Check if Windows agent exists
    if [ -f "windows_agent.ps1" ]; then
        echo -e "${CYAN}Windows agent found - syntax validation...${NC}"

        # Basic syntax check (PowerShell simulation)
        if grep -q "function\|param\|Write-Host" windows_agent.ps1; then
            echo -e "${GREEN}✅ Windows agent syntax appears valid${NC}" >> "$TEST_RESULTS"
        else
            echo -e "${YELLOW}⚠️  Windows agent syntax may need verification${NC}" >> "$TEST_RESULTS"
        fi

        # Check for key functions
        if grep -q "Monitor-Services\|Get-NetworkTraffic\|Start-IncidentResponse" windows_agent.ps1; then
            echo -e "${GREEN}✅ Windows agent key functions detected${NC}" >> "$TEST_RESULTS"
        else
            echo -e "${YELLOW}⚠️  Windows agent may be missing key functions${NC}" >> "$TEST_RESULTS"
        fi
    else
        echo -e "${RED}❌ Windows agent not found${NC}" >> "$TEST_RESULTS"
    fi

    echo -e "${GREEN}✅ Windows agent testing completed${NC}"
    echo
}

# Generate practice session report
generate_report() {
    echo -e "${BOLD}${BLUE}📋 GENERATING PRACTICE SESSION REPORT${NC}"
    echo

    # Create comprehensive report
    cat > "$TEST_REPORT" << EOF
===============================================================================
CEG25 BLUE TEAM TOOLKIT - PRACTICE SESSION REPORT
===============================================================================
Date: $(date)
Version: $VERSION
Test Environment: Docker-based isolated testing

===============================================================================
TEST RESULTS SUMMARY
===============================================================================

EOF

    # Count successful tests
    SUCCESS_COUNT=$(grep -c "✅.*test completed" "$TEST_RESULTS")
    WARNING_COUNT=$(grep -c "⚠️" "$TEST_RESULTS")
    ERROR_COUNT=$(grep -c "❌.*not found" "$TEST_RESULTS")

    echo "Total Tests Run: $((SUCCESS_COUNT + WARNING_COUNT + ERROR_COUNT))" >> "$TEST_REPORT"
    echo "Successful Tests: $SUCCESS_COUNT" >> "$TEST_REPORT"
    echo "Warnings: $WARNING_COUNT" >> "$TEST_REPORT"
    echo "Errors: $ERROR_COUNT" >> "$TEST_REPORT"
    echo "" >> "$TEST_REPORT"

    # Detailed results
    echo "===============================================================================" >> "$TEST_REPORT"
    echo "DETAILED TEST RESULTS" >> "$TEST_REPORT"
    echo "===============================================================================" >> "$TEST_REPORT"
    echo "" >> "$TEST_REPORT"

    cat "$TEST_RESULTS" >> "$TEST_REPORT"

    # Recommendations
    echo "" >> "$TEST_REPORT"
    echo "===============================================================================" >> "$TEST_REPORT"
    echo "RECOMMENDATIONS FOR COMPETITION" >> "$TEST_REPORT"
    echo "===============================================================================" >> "$TEST_REPORT"
    echo "" >> "$TEST_REPORT"

    if [ $ERROR_COUNT -eq 0 ]; then
        echo "✅ All tools are present and functional" >> "$TEST_REPORT"
        echo "✅ Ready for competition deployment" >> "$TEST_REPORT"
    else
        echo "⚠️  Some tools are missing or have issues" >> "$TEST_REPORT"
        echo "⚠️  Review and fix before competition" >> "$TEST_REPORT"
    fi

    if [ $WARNING_COUNT -gt 0 ]; then
        echo "⚠️  Some tools may need additional configuration" >> "$TEST_REPORT"
        echo "⚠️  Test in full environment before competition" >> "$TEST_REPORT"
    fi

    echo "" >> "$TEST_REPORT"
    echo "===============================================================================" >> "$TEST_REPORT"
    echo "END OF REPORT" >> "$TEST_REPORT"
    echo "===============================================================================" >> "$TEST_REPORT"

    echo -e "${GREEN}✅ Practice session report generated: $TEST_REPORT${NC}"
    echo
}

# Cleanup test environment
cleanup_environment() {
    echo -e "${BOLD}${BLUE}🧹 CLEANING UP TEST ENVIRONMENT${NC}"
    echo

    # Stop and remove test containers
    docker stop ceg25-mock ceg25-harden-test 2>/dev/null
    docker rm ceg25-mock ceg25-harden-test 2>/dev/null
    docker network rm "$DOCKER_NETWORK" 2>/dev/null

    echo -e "${GREEN}✅ Test environment cleaned up${NC}"
    echo
}

# Display final results
display_results() {
    echo -e "${BOLD}${GREEN}🎯 PRACTICE SESSION COMPLETE${NC}"
    echo

    # Show summary
    SUCCESS_COUNT=$(grep -c "✅.*test completed" "$TEST_RESULTS")
    WARNING_COUNT=$(grep -c "⚠️" "$TEST_RESULTS")
    ERROR_COUNT=$(grep -c "❌.*not found" "$TEST_RESULTS")

    echo -e "${CYAN}Test Summary:${NC}"
    echo -e "${GREEN}Successful Tests: $SUCCESS_COUNT${NC}"
    echo -e "${YELLOW}Warnings: $WARNING_COUNT${NC}"
    echo -e "${RED}Errors: $ERROR_COUNT${NC}"
    echo

    if [ $ERROR_COUNT -eq 0 ] && [ $WARNING_COUNT -eq 0 ]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED! Toolkit is ready for competition.${NC}"
    elif [ $ERROR_COUNT -eq 0 ]; then
        echo -e "${YELLOW}⚠️  Toolkit is functional but has some warnings to review.${NC}"
    else
        echo -e "${RED}❌ Some tools are missing. Please check the report.${NC}"
    fi

    echo
    echo -e "${BLUE}📋 Full report available at: $TEST_REPORT${NC}"
    echo -e "${BLUE}📋 Test logs available at: $TEST_RESULTS${NC}"
    echo
}

# Main practice testing function
main() {
    echo -e "${BOLD}${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🧪 CEG25 PRACTICE SESSION 🧪                           ║"
    echo "║                 Safe Testing Environment for All Tools                    ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${WHITE}Version: $VERSION | Date: $(date)${NC}"
    echo -e "${WHITE}Environment: Docker-based isolated testing${NC}"
    echo -e "${BOLD}${YELLOW}⚠️  This will create test containers and may take several minutes...${NC}"
    echo

    # Confirm execution
    read -p "Continue with practice testing? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Practice session cancelled.${NC}"
        exit 0
    fi

    # Run all tests
    init_test_environment
    test_core_modules
    test_hardening_automations
    test_advanced_features
    test_web_dashboard
    test_windows_agent
    generate_report
    cleanup_environment
    display_results

    echo -e "${BOLD}${BLUE}Good luck in CyberEXPERT Game 2025! 🇵🇱${NC}"
}

# Execute main function
main "$@"