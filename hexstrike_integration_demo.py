#!/usr/bin/env python3
"""
HexStrike + Blue Team Toolkit Integration Demo

This demonstrates the unified security platform combining:
- HexStrike AI (150+ Red Team tools)
- Blue Team Toolkit (20+ Blue Team modules)
- AI-powered automation via MCP

Usage Examples for AI Agents (Claude, GPT-4, Copilot):
"""

# ===============================================================================
# 🎯 HYBRID SECURITY OPERATIONS WORKFLOW
# ===============================================================================

def competition_workflow_example():
    """
    Example AI Agent workflow for CyberEXPERT Game 2025
    """
    
    print("""
🏆 CyberEXPERT Game 2025 - Hybrid AI Security Operations

Phase 1: Blue Team Defense Setup (AI Agent Commands)
════════════════════════════════════════════════════

AI: "Start CEG25 competition defense for energy infrastructure"
    → blue_team_compete(duration=7200, auto_harden=True, auto_scan_interval=900)
    → Result: Automated defense active for 2 hours

AI: "Launch real-time monitoring dashboard"  
    → blue_team_monitor_start(duration=0, interval=10)
    → Result: Continuous threat detection active

AI: "Generate baseline security report"
    → blue_team_report(format_type="html", include_recommendations=True)
    → Result: Professional report for competition documentation

Phase 2: Red Team Intelligence (HexStrike AI Tools)
═══════════════════════════════════════════════════

AI: "Scan energy infrastructure for vulnerabilities"
    → nmap_scan(target="10.83.0.0/16", scan_type="-sV -sC", ports="80,443,502,2049")
    → nuclei_scan(target="discovered_hosts", severity="critical,high")
    → Result: SCADA/ICS vulnerabilities identified

AI: "Test our defensive hardening"
    → rustscan_fast_scan(target="localhost", ports="1-65535")
    → sqlmap_scan(url="http://localhost/app", data="")
    → Result: Validate blue team hardening effectiveness

Phase 3: Adaptive Response (Hybrid Operations)
══════════════════════════════════════════════

AI: "Threat detected on SCADA network, respond immediately"
    → blue_team_scan(scan_type="all", sudo=True)          # Assess current state
    → blue_team_harden(action="all", sudo=True)           # Apply all fixes
    → nmap_scan(target="10.83.2.0/24", scan_type="-sS")   # Verify network state
    → blue_team_report(format_type="text")                # Document response

AI: "Competition final phase - maximum security"
    → blue_team_ceg25_assess()                            # CEG25 energy assessment
    → blue_team_compete(duration=3600, auto_harden=True)  # Final hour automation
    → Result: Maximum scoring optimization

═════════════════════════════════════════════════════════════════════════════
""")

def mcp_tools_available():
    """
    Complete list of tools available to AI agents via HexStrike MCP
    """
    
    tools = {
        "Blue Team Operations (8 tools)": [
            "blue_team_scan(scan_type, sudo)",
            "blue_team_harden(action, sudo, backup)", 
            "blue_team_monitor_start(duration, interval)",
            "blue_team_monitor_stop()",
            "blue_team_monitor_status()",
            "blue_team_report(format_type, include_recommendations)",
            "blue_team_compete(duration, auto_harden, auto_scan_interval)",
            "blue_team_ceg25_assess()"
        ],
        
        "Red Team Operations (150+ tools)": [
            "nmap_scan(target, scan_type, ports)",
            "nuclei_scan(target, severity, tags)",
            "gobuster_scan(url, mode, wordlist)", 
            "sqlmap_scan(url, data)",
            "rustscan_fast_scan(target, ports)",
            "hydra_attack(target, service, username)",
            "john_crack(hash_file, wordlist)",
            "hashcat_crack(hash_file, hash_type)",
            "binwalk_analyze(file_path, extract)",
            "volatility_analyze(memory_file, plugin)",
            "# ... 140+ more tools available"
        ],
        
        "AI Agent Capabilities": [
            "Autonomous decision making",
            "Real-time threat response", 
            "Competition strategy optimization",
            "Multi-vector attack coordination",
            "Intelligent hardening prioritization",
            "Cross-platform tool orchestration"
        ]
    }
    
    print("🤖 AI Agent Tool Arsenal:")
    print("=" * 60)
    
    for category, tool_list in tools.items():
        print(f"\n📋 {category}:")
        for tool in tool_list:
            print(f"   • {tool}")

def integration_benefits():
    """
    Benefits of the integrated platform
    """
    
    print("""
🚀 Integration Benefits - Best of Both Worlds

🛡️ Blue Team Advantages:
   ✅ 20+ specialized defense modules
   ✅ CEG25 energy infrastructure focus  
   ✅ Real-time monitoring & alerting
   ✅ Automated hardening (8 categories)
   ✅ Competition scoring optimization
   ✅ Professional reporting system

🔴 Red Team Advantages:
   ✅ 150+ offensive security tools
   ✅ AI-powered decision engine
   ✅ Advanced exploitation chains
   ✅ Comprehensive vulnerability scanning
   ✅ Multi-vector attack simulation
   ✅ Cross-platform coverage

🤖 AI Orchestration:
   ✅ Autonomous threat response
   ✅ Strategic competition planning
   ✅ Real-time adaptation to threats
   ✅ Intelligent tool selection
   ✅ Performance optimization
   ✅ Unified command interface

🎯 Competition Advantages:
   ✅ Hybrid defense/offense strategy
   ✅ Real-time threat intelligence
   ✅ Automated baseline operations
   ✅ Strategic AI decision making
   ✅ Maximum scoring potential
   ✅ Comprehensive coverage

Performance Metrics:
   • Blue Team: 20-30 second scans vs 30+ minutes manual
   • Red Team: 150+ tools vs ~20 typical toolkit
   • AI Agent: Real-time response vs human decision delays
   • Integration: Unified platform vs tool switching overhead
""")

def main():
    """
    Main demo function
    """
    print("🎯 HexStrike AI + Blue Team Toolkit Integration")
    print("="*60)
    
    print("\n1. Competition Workflow Example:")
    competition_workflow_example()
    
    print("\n2. Available MCP Tools:")
    mcp_tools_available()
    
    print("\n3. Integration Benefits:")
    integration_benefits()
    
    print("""
🏆 Ready for CyberEXPERT Game 2025!

Your AI Agent can now:
• Autonomously defend energy infrastructure
• Intelligently attack test systems  
• Adapt strategies in real-time
• Optimize competition scoring
• Coordinate 170+ security tools

Competition Date: October 28-30, 2025 | Warsaw, Poland
""")

if __name__ == "__main__":
    main()