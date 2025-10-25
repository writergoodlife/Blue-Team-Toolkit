#!/usr/bin/env python3
"""
CEG25 Blue Team Dashboard - Simulation Test Script
Tests the simulation functionality of the dashboard
"""

import requests
import time
import json

# Dashboard API base URL
BASE_URL = "http://localhost:5000"

def test_simulation_features():
    """Test all simulation features"""
    print("🧪 Testing CEG25 Blue Team Dashboard Simulation System")
    print("=" * 60)
    
    # Test 1: Check simulation status
    print("\n1. Checking simulation mode status...")
    try:
        response = requests.get(f"{BASE_URL}/api/simulation/status")
        if response.status_code == 200:
            status = response.json()
            print(f"   ✅ Simulation mode: {'ENABLED' if status['simulation'] else 'DISABLED'}")
        else:
            print(f"   ❌ Failed to get simulation status: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 2: Configure a tool
    print("\n2. Testing tool configuration...")
    config_data = {
        "target_ip": "10.0.0.0/24",
        "scan_type": "deep",
        "port_range": "1-65535"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/tool/blue_agent/config", 
                               json=config_data,
                               headers={'Content-Type': 'application/json'})
        if response.status_code == 200:
            print("   ✅ Blue Agent configuration updated successfully")
            print(f"   📋 Config: {config_data}")
        else:
            print(f"   ❌ Configuration failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 3: Start a tool simulation
    print("\n3. Starting Blue Agent simulation...")
    try:
        response = requests.post(f"{BASE_URL}/api/tool/blue_agent/start")
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Tool started: {result['status']}")
            print(f"   🔧 Mode: {result.get('mode', 'unknown')}")
            print(f"   ⚙️  Config: {result.get('config_args', [])}")
            
            # Wait and check status
            print("\n4. Monitoring simulation progress...")
            for i in range(5):
                time.sleep(2)
                status_response = requests.get(f"{BASE_URL}/api/tool/blue_agent/status")
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    print(f"   📊 Status check {i+1}: {status_data.get('status', 'unknown')}")
                
                # Check metrics
                metrics_response = requests.get(f"{BASE_URL}/api/tool/blue_agent/metrics")
                if metrics_response.status_code == 200:
                    metrics = metrics_response.json()
                    print(f"   📈 Alerts: {metrics.get('alerts', 0)}, Findings: {metrics.get('findings', 0)}")
                
        else:
            print(f"   ❌ Failed to start tool: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 4: Test multiple tools
    print("\n5. Testing multiple tool simulations...")
    tools_to_test = ['network_traffic_analyzer', 'firewall_hardening', 'multi_subnet_scanner']
    
    for tool in tools_to_test:
        try:
            response = requests.post(f"{BASE_URL}/api/tool/{tool}/start")
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ {tool}: {result['status']} ({result.get('mode', 'unknown')})")
            else:
                print(f"   ❌ {tool}: Failed ({response.status_code})")
        except Exception as e:
            print(f"   ❌ {tool}: Error - {e}")
    
    print("\n6. Checking global metrics...")
    try:
        response = requests.get(f"{BASE_URL}/api/global_metrics")
        if response.status_code == 200:
            global_data = response.json()
            metrics = global_data.get('global_metrics', {})
            print(f"   📊 Total Alerts: {metrics.get('total_alerts', 0)}")
            print(f"   🛡️  Security Score: {metrics.get('avg_security_score', 0)}")
            print(f"   🔥 Threats Blocked: {metrics.get('total_threats_blocked', 0)}")
        else:
            print(f"   ❌ Failed to get global metrics: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("🎯 Simulation test completed!")
    print("💡 Open http://localhost:5000 in your browser to see the live dashboard")
    print("🔧 Try starting tools and changing configurations to test interactively")

if __name__ == "__main__":
    test_simulation_features()