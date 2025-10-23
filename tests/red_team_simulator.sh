#!/bin/bash
#
# Red Team Simulator - For Testing Blue Team Agent
#
# This script simulates common red team actions to test the blue team agent's
# detection and remediation capabilities.
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           RED TEAM SIMULATOR - Testing Blue Agent             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Note: Some actions require sudo. Run with sudo for full simulation.${NC}"
fi

ACTION=$1

case "$ACTION" in
    "suid")
        echo -e "${RED}[RED TEAM]${NC} Creating malicious SUID backdoor..."
        sudo touch /tmp/red_team_backdoor
        sudo chmod u+s,g+s /tmp/red_team_backdoor
        sudo chmod 4755 /tmp/red_team_backdoor
        ls -l /tmp/red_team_backdoor
        echo -e "${GREEN}[✓] SUID backdoor created at /tmp/red_team_backdoor${NC}"
        ;;
    
    "writable")
        echo -e "${RED}[RED TEAM]${NC} Creating world-writable files for data exfil..."
        sudo touch /tmp/exfil_data.txt
        sudo chmod 777 /tmp/exfil_data.txt
        mkdir -p /tmp/red_team_staging
        sudo chmod 777 /tmp/red_team_staging
        ls -ld /tmp/exfil_data.txt /tmp/red_team_staging
        echo -e "${GREEN}[✓] World-writable files created${NC}"
        ;;
    
    "user")
        echo -e "${RED}[RED TEAM]${NC} Creating backdoor user account..."
        sudo useradd -m -s /bin/bash red_admin 2>/dev/null
        echo "red_admin:P@ssw0rd123" | sudo chpasswd
        echo -e "${GREEN}[✓] Backdoor user 'red_admin' created (password: P@ssw0rd123)${NC}"
        ;;
    
    "weakpass")
        echo -e "${RED}[RED TEAM]${NC} Creating user with weak password..."
        sudo useradd -m -s /bin/bash compromised_user 2>/dev/null
        echo "compromised_user:password" | sudo chpasswd
        echo -e "${GREEN}[✓] Compromised user created with weak password${NC}"
        ;;
    
    "port")
        echo -e "${RED}[RED TEAM]${NC} Opening backdoor listener on port 4444..."
        nohup nc -lvnp 4444 > /dev/null 2>&1 &
        NETCAT_PID=$!
        echo $NETCAT_PID > /tmp/red_team_netcat.pid
        sleep 1
        ss -tlnp | grep 4444
        echo -e "${GREEN}[✓] Backdoor listener on port 4444 (PID: $NETCAT_PID)${NC}"
        ;;
    
    "docker")
        echo -e "${RED}[RED TEAM]${NC} Creating privileged Docker container..."
        if command -v docker &> /dev/null; then
            sudo docker run -d --name red_team_container --privileged alpine sleep 3600 2>/dev/null
            echo -e "${GREEN}[✓] Privileged container 'red_team_container' created${NC}"
        else
            echo -e "${YELLOW}[!] Docker not available, skipping${NC}"
        fi
        ;;
    
    "all")
        echo -e "${RED}[RED TEAM]${NC} Deploying full attack simulation..."
        echo ""
        $0 suid
        echo ""
        $0 writable
        echo ""
        $0 user
        echo ""
        $0 weakpass
        echo ""
        $0 port
        echo ""
        $0 docker
        echo ""
        echo -e "${RED}[✓] All red team actions deployed!${NC}"
        ;;
    
    "clean")
        echo -e "${GREEN}[CLEANUP]${NC} Removing all red team artifacts..."
        
        # Remove SUID files
        sudo rm -f /tmp/red_team_backdoor /tmp/red_team_implant
        
        # Remove world-writable files
        sudo rm -rf /tmp/exfil_data.txt /tmp/red_team_staging /tmp/world_writable_test
        
        # Remove users
        sudo userdel -r red_admin 2>/dev/null
        sudo userdel -r compromised_user 2>/dev/null
        sudo userdel -r redteam_bkdr 2>/dev/null
        sudo userdel -r testuser 2>/dev/null
        
        # Kill netcat listener
        if [ -f /tmp/red_team_netcat.pid ]; then
            kill $(cat /tmp/red_team_netcat.pid) 2>/dev/null
            rm /tmp/red_team_netcat.pid
        fi
        pkill -f "nc -lvnp 4444" 2>/dev/null
        
        # Remove Docker container
        if command -v docker &> /dev/null; then
            sudo docker stop red_team_container 2>/dev/null
            sudo docker rm red_team_container 2>/dev/null
        fi
        
        echo -e "${GREEN}[✓] Cleanup complete!${NC}"
        ;;
    
    *)
        echo "Usage: $0 {suid|writable|user|weakpass|port|docker|all|clean}"
        echo ""
        echo "Simulate red team actions:"
        echo "  suid      - Create malicious SUID file"
        echo "  writable  - Create world-writable files"
        echo "  user      - Create backdoor user account"
        echo "  weakpass  - Create user with weak password"
        echo "  port      - Open backdoor listener"
        echo "  docker    - Create privileged container"
        echo "  all       - Run all simulations"
        echo "  clean     - Remove all artifacts"
        exit 1
        ;;
esac
