#!/usr/bin/env python3
"""
HexStrike Integration Test Script
Tests the Blue Team Toolkit integration with HexStrike AI MCP
"""

import requests
import json
import time
import sys

HEXSTRIKE_SERVER = "http://localhost:8888"

def test_server_health():
    """Test if HexStrike server is running"""
    try:
        response = requests.get(f"{HEXSTRIKE_SERVER}/health", timeout=5)
        if response.status_code == 200:
            print("✅ HexStrike server is running")
            return True
        else:
            print(f"❌ HexStrike server health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to HexStrike server: {e}")
        return False

def test_blue_team_scan():
    """Test Blue Team scan endpoint"""
    try:
        data = {
            "scan_type": "ports",
            "sudo": False  # Quick test without sudo
        }
        
        print("🔍 Testing Blue Team scan...")
        response = requests.post(f"{HEXSTRIKE_SERVER}/api/blueteam/scan", 
                               json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                print("✅ Blue Team scan test successful")
                print(f"   Findings: {result.get('findings', {})}")
                return True
            else:
                print(f"❌ Blue Team scan failed: {result.get('error')}")
                return False
        else:
            print(f"❌ Blue Team scan HTTP error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Blue Team scan test error: {e}")
        return False

def test_blue_team_report():
    """Test Blue Team report generation"""
    try:
        data = {
            "format": "text",
            "include_recommendations": True
        }
        
        print("📊 Testing Blue Team report...")
        response = requests.post(f"{HEXSTRIKE_SERVER}/api/blueteam/report", 
                               json=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                print("✅ Blue Team report test successful")
                print(f"   Report path: {result.get('report_path')}")
                return True
            else:
                print(f"❌ Blue Team report failed: {result.get('error')}")
                return False
        else:
            print(f"❌ Blue Team report HTTP error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Blue Team report test error: {e}")
        return False

def test_ceg25_assess():
    """Test CEG25 assessment endpoint"""
    try:
        print("⚡ Testing CEG25 assessment...")
        response = requests.post(f"{HEXSTRIKE_SERVER}/api/blueteam/ceg25/assess", 
                               json={}, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                print("✅ CEG25 assessment test successful")
                print(f"   Findings: {result.get('findings', {})}")
                return True
            else:
                print(f"❌ CEG25 assessment failed: {result.get('error')}")
                return False
        else:
            print(f"❌ CEG25 assessment HTTP error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ CEG25 assessment test error: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 HexStrike + Blue Team Toolkit Integration Test")
    print("=" * 60)
    
    tests = [
        ("Server Health", test_server_health),
        ("Blue Team Scan", test_blue_team_scan),
        ("Blue Team Report", test_blue_team_report),
        ("CEG25 Assessment", test_ceg25_assess)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running test: {test_name}")
        try:
            if test_func():
                passed += 1
            time.sleep(1)  # Brief pause between tests
        except Exception as e:
            print(f"❌ Test {test_name} crashed: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Integration is working perfectly!")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed. Check HexStrike server status.")
        sys.exit(1)

if __name__ == "__main__":
    main()