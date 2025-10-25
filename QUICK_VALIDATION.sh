#!/bin/bash

# ============================================================================
# CEG25 Blue Team Toolkit - Quick Practice Validation
# ============================================================================
# Fast validation of all tools without Docker containers
# Syntax checking, file validation, and basic functionality tests
# ============================================================================

VERSION="1.0"
SCRIPT_NAME="CEG25 Quick Validation"

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
TOOLKIT_DIR="/home/goodlife/Desktop/CEG25/blue-team-toolkit"
VALIDATION_RESULTS="/tmp/ceg25_validation_$(date +%Y%m%d_%H%M%S).log"
SCORE=0
TOTAL_TESTS=0

# Logging function
log() {
    echo "$1" | tee -a "$VALIDATION_RESULTS"
}

# Test file existence and permissions
test_file_presence() {
    local file="$1"
    local description="$2"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ -f "$file" ]; then
        if [ -x "$file" ]; then
            log "✅ $description - Present and executable"
            SCORE=$((SCORE + 1))
            return 0
        else
            log "⚠️  $description - Present but not executable"
            return 1
        fi
    else
        log "❌ $description - Missing"
        return 1
    fi
}

# Test script syntax
test_script_syntax() {
    local file="$1"
    local description="$2"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ -f "$file" ]; then
        if bash -n "$file" 2>/dev/null; then
            log "✅ $description - Syntax valid"
            SCORE=$((SCORE + 1))
            return 0
        else
            log "❌ $description - Syntax errors detected"
            return 1
        fi
    else
        log "❌ $description - File not found"
        return 1
    fi
}

# Test Python script syntax
test_python_syntax() {
    local file="$1"
    local description="$2"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ -f "$file" ]; then
        if python3 -m py_compile "$file" 2>/dev/null; then
            log "✅ $description - Syntax valid"
            SCORE=$((SCORE + 1))
            return 0
        else
            log "❌ $description - Syntax errors detected"
            return 1
        fi
    else
        log "❌ $description - File not found"
        return 1
    fi
}

# Test PowerShell script syntax (basic)
test_powershell_syntax() {
    local file="$1"
    local description="$2"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ -f "$file" ]; then
        # Basic PowerShell syntax check
        if grep -q "function\|param\|Write-Host\|Get-" "$file"; then
            log "✅ $description - Basic PowerShell structure detected"
            SCORE=$((SCORE + 1))
            return 0
        else
            log "⚠️  $description - May not be valid PowerShell"
            return 1
        fi
    else
        log "❌ $description - File not found"
        return 1
    fi
}

# Test configuration files
test_config_files() {
    local file="$1"
    local description="$2"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ -f "$file" ]; then
        log "✅ $description - Configuration file present"
        SCORE=$((SCORE + 1))
        return 0
    else
        log "❌ $description - Configuration file missing"
        return 1
    fi
}

# Main validation function
main() {
    echo -e "${BOLD}${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                 🔍 CEG25 QUICK VALIDATION 🔍                             ║"
    echo "║             Fast Tool Validation Without Docker Containers                 ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${WHITE}Version: $VERSION | Date: $(date)${NC}"
    echo -e "${WHITE}Testing: File presence, permissions, and basic syntax${NC}"
    echo

    # Initialize log file
    echo "CEG25 Blue Team Toolkit - Quick Validation Report" > "$VALIDATION_RESULTS"
    echo "Date: $(date)" >> "$VALIDATION_RESULTS"
    echo "Version: $VERSION" >> "$VALIDATION_RESULTS"
    echo "=================================================================" >> "$VALIDATION_RESULTS"
    echo "" >> "$VALIDATION_RESULTS"

    echo -e "${BOLD}${BLUE}🔧 VALIDATING CORE SECURITY MODULES${NC}"
    echo

    # Test core security modules
    test_file_presence "$TOOLKIT_DIR/linux/scada_ics_security.sh" "SCADA/ICS Security Scanner"
    test_script_syntax "$TOOLKIT_DIR/linux/scada_ics_security.sh" "SCADA/ICS Scanner Syntax"

    test_file_presence "$TOOLKIT_DIR/linux/multi_subnet_scanner.sh" "Multi-Subnet Network Scanner"
    test_script_syntax "$TOOLKIT_DIR/linux/multi_subnet_scanner.sh" "Network Scanner Syntax"

    test_file_presence "$TOOLKIT_DIR/linux/industrial_protocol_monitor.sh" "Industrial Protocol Monitor"
    test_script_syntax "$TOOLKIT_DIR/linux/industrial_protocol_monitor.sh" "Protocol Monitor Syntax"

    test_file_presence "$TOOLKIT_DIR/linux/energy_vulnerability_scanner.sh" "Energy Vulnerability Scanner"
    test_script_syntax "$TOOLKIT_DIR/linux/energy_vulnerability_scanner.sh" "Vulnerability Scanner Syntax"

    test_file_presence "$TOOLKIT_DIR/linux/ceg25_competition.sh" "CEG25 Competition Orchestrator"
    test_script_syntax "$TOOLKIT_DIR/linux/ceg25_competition.sh" "Competition Orchestrator Syntax"

    echo -e "${BOLD}${BLUE}🔒 VALIDATING HARDENING AUTOMATIONS${NC}"
    echo

    # Test hardening automations
    test_file_presence "$TOOLKIT_DIR/linux/ssh_hardening.sh" "SSH Security Hardening"
    test_script_syntax "$TOOLKIT_DIR/linux/ssh_hardening.sh" "SSH Hardening Syntax"

    test_file_presence "$TOOLKIT_DIR/linux/firewall_hardening.sh" "Firewall Hardening"
    test_script_syntax "$TOOLKIT_DIR/linux/firewall_hardening.sh" "Firewall Hardening Syntax"

    test_file_presence "$TOOLKIT_DIR/linux/docker_security.sh" "Docker Security Hardening"
    test_script_syntax "$TOOLKIT_DIR/linux/docker_security.sh" "Docker Security Syntax"

    echo -e "${BOLD}${BLUE}📊 VALIDATING ADVANCED FEATURES${NC}"
    echo

    # Test advanced features
    test_file_presence "$TOOLKIT_DIR/linux/network_traffic_analyzer.sh" "Network Traffic Analyzer"
    test_script_syntax "$TOOLKIT_DIR/linux/network_traffic_analyzer.sh" "Traffic Analyzer Syntax"

    test_file_presence "$TOOLKIT_DIR/linux/incident_response_playbooks.sh" "Incident Response Playbooks"
    test_script_syntax "$TOOLKIT_DIR/linux/incident_response_playbooks.sh" "Incident Response Syntax"

    test_file_presence "$TOOLKIT_DIR/linux/automated_service_restoration.sh" "Automated Service Restoration"
    test_script_syntax "$TOOLKIT_DIR/linux/automated_service_restoration.sh" "Service Restoration Syntax"

    echo -e "${BOLD}${BLUE}🌐 VALIDATING WEB DASHBOARD${NC}"
    echo

    # Test web dashboard
    test_file_presence "$TOOLKIT_DIR/web_dashboard.py" "Web Dashboard"
    test_python_syntax "$TOOLKIT_DIR/web_dashboard.py" "Web Dashboard Syntax"
    test_config_files "$TOOLKIT_DIR/requirements-dashboard.txt" "Dashboard Requirements"

    echo -e "${BOLD}${BLUE}🪟 VALIDATING WINDOWS AGENT${NC}"
    echo

    # Test Windows agent
    test_file_presence "$TOOLKIT_DIR/windows/windows_agent.ps1" "Windows Agent"
    test_powershell_syntax "$TOOLKIT_DIR/windows/windows_agent.ps1" "Windows Agent Structure"

    echo -e "${BOLD}${BLUE}📋 VALIDATING CONFIGURATION FILES${NC}"
    echo

    # Test configuration files
    test_config_files "$TOOLKIT_DIR/COMPLETION_SUMMARY.sh" "Completion Summary"
    test_config_files "$TOOLKIT_DIR/PRACTICE_TESTING.sh" "Practice Testing Script"

    # Calculate percentage
    PERCENTAGE=$((SCORE * 100 / TOTAL_TESTS))

    echo -e "${BOLD}${BLUE}📊 VALIDATION RESULTS${NC}"
    echo

    echo "=================================================================" >> "$VALIDATION_RESULTS"
    echo "VALIDATION SUMMARY" >> "$VALIDATION_RESULTS"
    echo "=================================================================" >> "$VALIDATION_RESULTS"
    echo "Tests Passed: $SCORE / $TOTAL_TESTS" >> "$VALIDATION_RESULTS"
    echo "Success Rate: $PERCENTAGE%" >> "$VALIDATION_RESULTS"
    echo "" >> "$VALIDATION_RESULTS"

    # Display results
    echo -e "${CYAN}Validation Summary:${NC}"
    echo -e "${WHITE}Tests Passed: ${GREEN}$SCORE${WHITE} / ${WHITE}$TOTAL_TESTS${NC}"
    echo -e "${WHITE}Success Rate: ${GREEN}$PERCENTAGE%${NC}"
    echo

    if [ $PERCENTAGE -eq 100 ]; then
        echo -e "${GREEN}🎉 PERFECT! All tools are present and syntactically correct.${NC}"
        echo -e "${GREEN}✅ Ready for competition deployment.${NC}"
    elif [ $PERCENTAGE -ge 90 ]; then
        echo -e "${YELLOW}⚠️  Excellent! Minor issues detected.${NC}"
        echo -e "${YELLOW}🔧 Review warnings before competition.${NC}"
    elif [ $PERCENTAGE -ge 75 ]; then
        echo -e "${YELLOW}⚠️  Good! Some tools need attention.${NC}"
        echo -e "${YELLOW}🔧 Fix issues before competition.${NC}"
    else
        echo -e "${RED}❌ Critical issues detected.${NC}"
        echo -e "${RED}🔧 Major fixes required before competition.${NC}"
    fi

    echo
    echo -e "${BLUE}📋 Detailed report saved to: $VALIDATION_RESULTS${NC}"
    echo

    # Show critical issues if any
    ERROR_COUNT=$(grep -c "❌" "$VALIDATION_RESULTS")
    if [ $ERROR_COUNT -gt 0 ]; then
        echo -e "${RED}Critical Issues Found:${NC}"
        grep "❌" "$VALIDATION_RESULTS"
        echo
    fi

    # Show warnings if any
    WARNING_COUNT=$(grep -c "⚠️" "$VALIDATION_RESULTS")
    if [ $WARNING_COUNT -gt 0 ]; then
        echo -e "${YELLOW}Warnings:${NC}"
        grep "⚠️" "$VALIDATION_RESULTS"
        echo
    fi

    echo -e "${BOLD}${BLUE}Next Steps:${NC}"
    echo -e "${WHITE}1. Review the detailed report: ${CYAN}$VALIDATION_RESULTS${NC}"
    echo -e "${WHITE}2. Fix any critical issues found${NC}"
    echo -e "${WHITE}3. Test tools in isolated environment${NC}"
    echo -e "${WHITE}4. Practice deployment procedures${NC}"
    echo
    echo -e "${BOLD}${GREEN}Good luck in CyberEXPERT Game 2025! 🇵🇱${NC}"
}

# Execute main function
main "$@"