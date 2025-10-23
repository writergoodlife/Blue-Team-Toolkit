#!/bin/bash
#
# Monitor Module Test - Validates Real-Time Monitoring
#
# This script tests all monitoring capabilities to ensure real-time
# detection works correctly.
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          Monitor Module Test - Real-Time Detection            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Configuration
AGENT_PATH="../linux/blue_agent.sh"
LOG_FILE="../logs/blue_agent.log"
TEST_DURATION=30
PASS_COUNT=0
FAIL_COUNT=0

# Test helper functions
test_passed() {
    echo -e "${GREEN}[✓ PASS]${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

test_failed() {
    echo -e "${RED}[✗ FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

test_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Test 1: Monitor Start/Stop
echo ""
echo -e "${BLUE}═══ Test 1: Monitor Start/Stop ═══${NC}"
test_info "Starting monitor for $TEST_DURATION seconds..."

sudo $AGENT_PATH monitor --duration $TEST_DURATION > /dev/null 2>&1 &
MONITOR_START_PID=$!

sleep 3

# Check if monitor is running
if sudo $AGENT_PATH monitor status 2>&1 | grep -q "Status: RUNNING"; then
    test_passed "Monitor started successfully"
else
    test_failed "Monitor failed to start"
fi

# Wait for monitor to complete (with timeout)
test_info "Waiting for monitor to complete duration ($TEST_DURATION seconds)..."
timeout $((TEST_DURATION + 10)) bash -c "while sudo $AGENT_PATH monitor status 2>&1 | grep -q 'Status: RUNNING'; do sleep 2; done" 2>/dev/null

# Give it a moment to clean up
sleep 2

# Check if monitor stopped
if sudo $AGENT_PATH monitor status 2>&1 | grep -q "NOT RUNNING"; then
    test_passed "Monitor stopped automatically after duration"
else
    test_failed "Monitor did not stop after duration"
fi

# Test 2: SUID Detection
echo ""
echo -e "${BLUE}═══ Test 2: SUID File Detection ═══${NC}"
test_info "Creating test SUID file in /tmp..."

# Clear old logs
> $LOG_FILE

# Start monitor
sudo $AGENT_PATH monitor --duration $TEST_DURATION > /dev/null 2>&1 &
MONITOR_PID=$!
sleep 5

# Create SUID file
sudo touch /tmp/monitor_test_suid_$$
sudo chmod u+s /tmp/monitor_test_suid_$$
test_info "Created /tmp/monitor_test_suid_$$"

# Wait for detection
sleep 15

# Check logs
if grep -q "SUID/SGID file detected.*monitor_test_suid_$$" $LOG_FILE; then
    test_passed "SUID file detected in real-time"
else
    test_failed "SUID file not detected"
fi

# Cleanup
sudo rm -f /tmp/monitor_test_suid_$$
wait $MONITOR_PID 2>/dev/null

# Test 3: Network Port Detection
echo ""
echo -e "${BLUE}═══ Test 3: Network Port Detection ═══${NC}"
test_info "Starting test listener on port 9999..."

# Clear old logs
> $LOG_FILE

# Start monitor
sudo $AGENT_PATH monitor --duration $TEST_DURATION > /dev/null 2>&1 &
MONITOR_PID=$!
sleep 5

# Start test listener
nc -lvnp 9999 > /dev/null 2>&1 &
NC_PID=$!
test_info "Started netcat listener (PID: $NC_PID)"

# Wait for detection
sleep 15

# Check logs
if grep -q "New listening port detected.*9999" $LOG_FILE; then
    test_passed "New listening port detected"
else
    test_failed "New listening port not detected"
fi

# Cleanup
kill $NC_PID 2>/dev/null
wait $MONITOR_PID 2>/dev/null

# Test 4: File Integrity Monitoring
echo ""
echo -e "${BLUE}═══ Test 4: File Integrity Monitoring ═══${NC}"
test_info "Testing file integrity detection..."

# Clear old logs and create fresh baseline
> $LOG_FILE
rm -rf ../logs/monitor/
sudo $AGENT_PATH monitor --duration 15 > /dev/null 2>&1 &
wait $! 2>/dev/null

test_info "Baseline created, modifying /etc/hosts..."

# Start new monitor
sudo $AGENT_PATH monitor --duration $TEST_DURATION > /dev/null 2>&1 &
MONITOR_PID=$!
sleep 5

# Modify /etc/hosts
sudo bash -c 'echo "# Monitor test comment" >> /etc/hosts'
test_info "Modified /etc/hosts"

# Wait for detection
sleep 15

# Check logs
if grep -q "File integrity violation.*hosts" $LOG_FILE; then
    test_passed "File integrity violation detected"
else
    test_info "Note: File integrity checks may take time to detect"
    test_failed "File integrity violation not detected"
fi

# Restore /etc/hosts
sudo sed -i '/# Monitor test comment/d' /etc/hosts
wait $MONITOR_PID 2>/dev/null

# Test 5: Process Monitoring
echo ""
echo -e "${BLUE}═══ Test 5: Suspicious Process Detection ═══${NC}"
test_info "Testing suspicious process detection..."

# Clear old logs
> $LOG_FILE

# Start monitor
sudo $AGENT_PATH monitor --duration $TEST_DURATION > /dev/null 2>&1 &
MONITOR_PID=$!
sleep 5

# Start suspicious process (nc listener)
nc -lvnp 4444 > /dev/null 2>&1 &
SUSPICIOUS_PID=$!
test_info "Started suspicious process: nc -lvnp 4444"

# Wait for detection
sleep 15

# Check logs
if grep -q "Suspicious process detected.*nc -l" $LOG_FILE; then
    test_passed "Suspicious process detected"
else
    test_failed "Suspicious process not detected"
fi

# Cleanup
kill $SUSPICIOUS_PID 2>/dev/null
wait $MONITOR_PID 2>/dev/null

# Test 6: Stop Command
echo ""
echo -e "${BLUE}═══ Test 6: Manual Stop Command ═══${NC}"
test_info "Testing manual stop functionality..."

# Start monitor
sudo $AGENT_PATH monitor > /dev/null 2>&1 &
sleep 3

# Verify running
if sudo $AGENT_PATH monitor status 2>&1 | grep -q "Status: RUNNING"; then
    test_passed "Monitor is running"
    
    # Stop monitor
    sudo $AGENT_PATH monitor stop > /dev/null 2>&1
    sleep 2
    
    # Verify stopped
    if sudo $AGENT_PATH monitor status 2>&1 | grep -q "NOT RUNNING"; then
        test_passed "Monitor stopped via stop command"
    else
        test_failed "Monitor did not stop"
    fi
else
    test_failed "Monitor did not start"
fi

# Test 7: Status Command
echo ""
echo -e "${BLUE}═══ Test 7: Status Command ═══${NC}"
test_info "Testing status command..."

# Start monitor
sudo $AGENT_PATH monitor --duration 20 > /dev/null 2>&1 &
sleep 3

# Check status
status_output=$(sudo $AGENT_PATH monitor status 2>&1)
if echo "$status_output" | grep -q "Status: RUNNING"; then
    test_passed "Status command shows running state"
    
    if echo "$status_output" | grep -q "PID:"; then
        test_passed "Status command shows PID"
    else
        test_failed "Status command does not show PID"
    fi
    
    if echo "$status_output" | grep -q "Runtime:"; then
        test_passed "Status command shows runtime"
    else
        test_failed "Status command does not show runtime"
    fi
else
    test_failed "Status command failed"
fi

# Wait for monitor to finish
sleep 20

# Test 8: Baseline Creation
echo ""
echo -e "${BLUE}═══ Test 8: Baseline Creation ═══${NC}"
test_info "Testing baseline creation..."

# Remove old baselines
rm -rf ../logs/monitor/

# Start monitor
sudo $AGENT_PATH monitor --duration 10 > /dev/null 2>&1 &
wait $! 2>/dev/null

# Check if baselines were created
if [ -f ../logs/monitor/file_integrity.db ]; then
    test_passed "File integrity baseline created"
else
    test_failed "File integrity baseline not created"
fi

if [ -f ../logs/monitor/process_baseline.txt ]; then
    test_passed "Process baseline created"
else
    test_failed "Process baseline not created"
fi

if [ -f ../logs/monitor/network_baseline.txt ]; then
    test_passed "Network baseline created"
else
    test_failed "Network baseline not created"
fi

# Summary
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                      Test Results Summary                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "Tests Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Tests Failed: ${RED}$FAIL_COUNT${NC}"
echo -e "Total Tests:  $((PASS_COUNT + FAIL_COUNT))"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║             ✓ ALL TESTS PASSED - MONITOR READY!                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║               ✗ SOME TESTS FAILED - REVIEW NEEDED              ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
