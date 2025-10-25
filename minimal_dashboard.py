#!/usr/bin/env python3

import os
import sys
import json
import glob
import subprocess
import time
import threading
import random
import psutil
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Simulation system for testing tools
simulation_mode = True  # Set to True for simulation testing

# Simulation data generators
def generate_simulation_logs(tool_id, config_params=None):
    """Generate realistic log entries for tool simulation"""
    logs = {
        'blue_agent': [
            f"[{datetime.now().strftime('%H:%M:%S')}] Starting Blue Agent scan on {config_params.get('target_ip', '192.168.1.0/24')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Scan type: {config_params.get('scan_type', 'quick')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Port range: {config_params.get('port_range', '1-1000')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Discovered 15 active hosts",
            f"[{datetime.now().strftime('%H:%M:%S')}] Found 3 potential security issues",
            f"[{datetime.now().strftime('%H:%M:%S')}] Applying automated remediation...",
            f"[{datetime.now().strftime('%H:%M:%S')}] Blocked 2 suspicious connections",
        ],
        'network_traffic_analyzer': [
            f"[{datetime.now().strftime('%H:%M:%S')}] Starting packet capture on {config_params.get('capture_interface', 'any')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Filter: {config_params.get('packet_filter', 'tcp or udp')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Analysis depth: {config_params.get('analysis_depth', 'headers')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Captured 1,247 packets in last minute",
            f"[{datetime.now().strftime('%H:%M:%S')}] Detected potential DDoS pattern",
            f"[{datetime.now().strftime('%H:%M:%S')}] Bandwidth usage: 45.2 Mbps",
            f"[{datetime.now().strftime('%H:%M:%S')}] Found 2 suspicious network flows",
        ],
        'firewall_hardening': [
            f"[{datetime.now().strftime('%H:%M:%S')}] Hardening firewall on interface {config_params.get('interface', 'eth0')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Trusted networks: {config_params.get('trusted_networks', '192.168.1.0/24')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Hardening level: {config_params.get('hardening_level', 'medium')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Added 15 new firewall rules",
            f"[{datetime.now().strftime('%H:%M:%S')}] Updated 8 security policies",
            f"[{datetime.now().strftime('%H:%M:%S')}] Blocked 127 malicious attempts",
            f"[{datetime.now().strftime('%H:%M:%S')}] Security level increased to 95%",
        ],
        'multi_subnet_scanner': [
            f"[{datetime.now().strftime('%H:%M:%S')}] Scanning subnets: {config_params.get('subnet_list', '192.168.1.0/24,10.0.1.0/24')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Scan speed: {config_params.get('scan_speed', 'normal')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Port discovery: {'enabled' if config_params.get('port_discovery') else 'disabled'}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Subnet 192.168.1.0/24: 23 hosts found",
            f"[{datetime.now().strftime('%H:%M:%S')}] Subnet 10.0.1.0/24: 8 hosts found",
            f"[{datetime.now().strftime('%H:%M:%S')}] Total open ports: 156",
            f"[{datetime.now().strftime('%H:%M:%S')}] Security issues found: 4",
        ],
        'ssh_hardening': [
            f"[{datetime.now().strftime('%H:%M:%S')}] Hardening SSH on port {config_params.get('ssh_port', '22')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Allowed users: {config_params.get('allowed_users', 'admin,security')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Key algorithm: {config_params.get('key_algorithm', 'ed25519')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Updated SSH configuration",
            f"[{datetime.now().strftime('%H:%M:%S')}] Generated new host keys",
            f"[{datetime.now().strftime('%H:%M:%S')}] Applied security hardening",
            f"[{datetime.now().strftime('%H:%M:%S')}] Blocked 15 failed login attempts",
        ],
        'scada_ics_security': [
            f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring HMI networks: {config_params.get('hmi_networks', '10.1.0.0/16')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] PLC range: {config_params.get('plc_range', '10.2.0.0/16')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Security mode: {config_params.get('security_level', 'monitoring')}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Discovered 12 ICS devices",
            f"[{datetime.now().strftime('%H:%M:%S')}] 3 security events detected",
            f"[{datetime.now().strftime('%H:%M:%S')}] PLC communications: normal",
            f"[{datetime.now().strftime('%H:%M:%S')}] Safety systems: operational",
        ]
    }
    
    # Generate default logs for tools not specifically defined
    if tool_id not in logs:
        logs[tool_id] = [
            f"[{datetime.now().strftime('%H:%M:%S')}] Starting {tool_id.replace('_', ' ').title()}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Configuration loaded successfully",
            f"[{datetime.now().strftime('%H:%M:%S')}] Initialization complete",
            f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring system status...",
            f"[{datetime.now().strftime('%H:%M:%S')}] Processing security data",
            f"[{datetime.now().strftime('%H:%M:%S')}] Analysis in progress...",
        ]
    
    return logs[tool_id]

def simulate_tool_execution(tool_id):
    """Simulate tool execution with realistic behavior"""
    tool = tool_scripts[tool_id]
    
    # Get current configuration parameters
    config_params = {}
    for param, config in tool['parameters'].items():
        config_params[param] = config.get('current', config['default'])
    
    # Generate initial logs
    logs = generate_simulation_logs(tool_id, config_params)
    
    # Simulate progressive log output
    for i, log_line in enumerate(logs):
        time.sleep(random.uniform(0.5, 2.0))  # Random delay between log entries
        
        # Emit log update
        socketio.emit('tool_logs_update', {
            'tool': tool_id,
            'logs': '\n'.join(logs[:i+1])
        })
        
        # Update metrics progressively
        if i % 2 == 0:  # Update metrics every other log entry
            update_simulation_metrics(tool_id, i, len(logs))
    
    # Final status update
    tool['status'] = 'completed'
    socketio.emit('tool_status_update', {
        'tool': tool_id,
        'status': 'completed',
        'running': False,
        'message': 'Simulation completed successfully'
    })

def update_simulation_metrics(tool_id, progress, total):
    """Update metrics during simulation"""
    tool = tool_scripts[tool_id]
    completion_ratio = (progress + 1) / total
    
    # Update metrics based on tool type and progress
    if tool_id == 'blue_agent':
        tool['metrics']['alerts'] = int(completion_ratio * 15)
        tool['metrics']['findings'] = int(completion_ratio * 8)
        tool['metrics']['remediations'] = int(completion_ratio * 5)
        tool['metrics']['threats_blocked'] = int(completion_ratio * 12)
    elif tool_id == 'network_traffic_analyzer':
        tool['metrics']['packets_analyzed'] = int(completion_ratio * 1247)
        tool['metrics']['threats_detected'] = int(completion_ratio * 3)
        tool['metrics']['bandwidth_usage'] = int(completion_ratio * 45.2)
        tool['metrics']['suspicious_flows'] = int(completion_ratio * 2)
    elif tool_id == 'firewall_hardening':
        tool['metrics']['rules_added'] = int(completion_ratio * 15)
        tool['metrics']['policies_updated'] = int(completion_ratio * 8)
        tool['metrics']['blocked_attempts'] = int(completion_ratio * 127)
        tool['metrics']['security_level'] = 85 + int(completion_ratio * 10)
    elif tool_id == 'multi_subnet_scanner':
        tool['metrics']['subnets_scanned'] = int(completion_ratio * 2)
        tool['metrics']['hosts_discovered'] = int(completion_ratio * 31)
        tool['metrics']['open_ports'] = int(completion_ratio * 156)
        tool['metrics']['security_issues'] = int(completion_ratio * 4)
    
    # Update uptime
    if tool['start_time']:
        uptime = (datetime.now() - tool['start_time']).total_seconds() / 3600
        tool['metrics']['uptime_hours'] = round(uptime, 2)
    
    # Emit metrics update
    socketio.emit('tool_metrics_update', {
        'tool': tool_id,
        'metrics': tool['metrics']
    })

# Enhanced Flask app with SocketIO
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ceg25-blue-team-dashboard-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global metrics tracking
global_metrics = {
    'security_alerts': 0,
    'threats_detected': 0,
    'incidents_resolved': 0,
    'vulnerabilities_found': 0,
    'network_anomalies': 0,
    'failed_logins': 0,
    'firewall_blocks': 0,
    'system_health': 'healthy'
}

# Tool configurations with configurable parameters
tool_scripts = {
    'blue_agent': {
        'name': 'Blue Agent',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/blue_agent.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/blue_agent.log',
        'parameters': {
            'target_ip': {'type': 'text', 'default': '192.168.1.0/24', 'label': 'Target Network'},
            'scan_type': {'type': 'select', 'options': ['quick', 'deep', 'stealth'], 'default': 'quick', 'label': 'Scan Type'},
            'port_range': {'type': 'text', 'default': '1-1000', 'label': 'Port Range'}
        },
        'metrics': {
            'alerts': 0, 
            'findings': 0, 
            'remediations': 0,
            'threats_blocked': 0,
            'scan_accuracy': 95.2,
            'uptime_hours': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'ceg25_competition': {
        'name': 'CEG25 Competition',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/ceg25_competition.sh',
        'args': ['run'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/ceg25/*.log',
        'parameters': {
            'competition_mode': {'type': 'select', 'options': ['practice', 'competition', 'defense'], 'default': 'practice', 'label': 'Mode'},
            'team_name': {'type': 'text', 'default': 'BlueTeam', 'label': 'Team Name'},
            'energy_sector': {'type': 'select', 'options': ['power_grid', 'oil_gas', 'renewable', 'all'], 'default': 'all', 'label': 'Energy Sector'}
        },
        'metrics': {
            'phases': 0, 
            'actions': 0,
            'completion_rate': 0,
            'score': 0,
            'energy_systems_protected': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'docker_security': {
        'name': 'Docker Security',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/docker_security.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/docker_security/*.log',
        'parameters': {
            'registry_url': {'type': 'text', 'default': 'localhost:5000', 'label': 'Docker Registry'},
            'scan_depth': {'type': 'select', 'options': ['basic', 'full', 'compliance'], 'default': 'full', 'label': 'Scan Depth'},
            'container_filter': {'type': 'text', 'default': '*', 'label': 'Container Filter'}
        },
        'metrics': {
            'containers': 0, 
            'issues': 0,
            'vulnerabilities': 0,
            'compliance_score': 98.5,
            'images_scanned': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'automated_service_restoration': {
        'name': 'Service Restoration',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/automated_service_restoration.sh',
        'args': ['restore'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/automated_service_restoration.log',
        'parameters': {
            'service_list': {'type': 'text', 'default': 'apache2,nginx,ssh,mysql', 'label': 'Services to Monitor'},
            'check_interval': {'type': 'number', 'default': '30', 'label': 'Check Interval (seconds)'},
            'auto_restart': {'type': 'checkbox', 'default': True, 'label': 'Auto Restart Failed Services'}
        },
        'metrics': {
            'services_restored': 0, 
            'failures': 0,
            'recovery_time_avg': 0,
            'success_rate': 100,
            'critical_services': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'energy_vulnerability_scanner': {
        'name': 'Energy Vulnerability Scanner',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/energy_vulnerability_scanner.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/energy_vulnerability_scanner.log',
        'parameters': {
            'scada_networks': {'type': 'text', 'default': '10.0.1.0/24,172.16.0.0/16', 'label': 'SCADA Networks'},
            'protocol_filter': {'type': 'select', 'options': ['modbus', 'dnp3', 'iec61850', 'all'], 'default': 'all', 'label': 'Protocol Focus'},
            'vulnerability_level': {'type': 'select', 'options': ['low', 'medium', 'high', 'critical'], 'default': 'medium', 'label': 'Min Severity'}
        },
        'metrics': {
            'vulnerabilities': 0, 
            'energy_devices': 0,
            'critical_vulns': 0,
            'risk_score': 0,
            'scada_systems': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'firewall_hardening': {
        'name': 'Firewall Hardening',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/firewall_hardening.sh',
        'args': ['harden'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/firewall_hardening.log',
        'parameters': {
            'interface': {'type': 'text', 'default': 'eth0', 'label': 'Network Interface'},
            'trusted_networks': {'type': 'text', 'default': '192.168.1.0/24,10.0.0.0/8', 'label': 'Trusted Networks'},
            'hardening_level': {'type': 'select', 'options': ['basic', 'medium', 'strict', 'maximum'], 'default': 'medium', 'label': 'Hardening Level'}
        },
        'metrics': {
            'rules_added': 0, 
            'policies_updated': 0,
            'blocked_attempts': 0,
            'security_level': 85,
            'threats_mitigated': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'incident_response_playbooks': {
        'name': 'Incident Response',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/incident_response_playbooks.sh',
        'args': ['monitor'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/incident_response_playbooks.log',
        'parameters': {
            'response_team': {'type': 'text', 'default': 'security@company.com', 'label': 'Response Team Email'},
            'escalation_time': {'type': 'number', 'default': '15', 'label': 'Escalation Time (minutes)'},
            'incident_types': {'type': 'text', 'default': 'malware,intrusion,ddos,data_breach', 'label': 'Incident Types to Monitor'}
        },
        'metrics': {
            'incidents': 0, 
            'responses': 0,
            'avg_response_time': 0,
            'escalations': 0,
            'resolution_rate': 100
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'industrial_protocol_monitor': {
        'name': 'Industrial Protocol Monitor',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/industrial_protocol_monitor.sh',
        'args': ['monitor'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/industrial_protocol_monitor.log',
        'parameters': {
            'monitor_interface': {'type': 'text', 'default': 'eth1', 'label': 'Monitor Interface'},
            'protocols': {'type': 'text', 'default': 'modbus,dnp3,iec61850,bacnet', 'label': 'Protocols to Monitor'},
            'anomaly_threshold': {'type': 'number', 'default': '5', 'label': 'Anomaly Threshold (%)'}
        },
        'metrics': {
            'protocols_monitored': 0, 
            'anomalies': 0,
            'modbus_packets': 0,
            'dnp3_messages': 0,
            'iec_communications': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'multi_subnet_scanner': {
        'name': 'Multi Subnet Scanner',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/multi_subnet_scanner.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/multi_subnet_scanner.log',
        'parameters': {
            'subnet_list': {'type': 'text', 'default': '192.168.1.0/24,10.0.1.0/24,172.16.0.0/16', 'label': 'Subnets to Scan'},
            'scan_speed': {'type': 'select', 'options': ['slow', 'normal', 'fast', 'aggressive'], 'default': 'normal', 'label': 'Scan Speed'},
            'port_discovery': {'type': 'checkbox', 'default': True, 'label': 'Enable Port Discovery'}
        },
        'metrics': {
            'subnets_scanned': 0, 
            'hosts_discovered': 0,
            'open_ports': 0,
            'security_issues': 0,
            'network_coverage': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'network_traffic_analyzer': {
        'name': 'Network Traffic Analyzer',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/network_traffic_analyzer.sh',
        'args': ['analyze'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/network_traffic_analyzer.log',
        'parameters': {
            'capture_interface': {'type': 'text', 'default': 'any', 'label': 'Capture Interface'},
            'packet_filter': {'type': 'text', 'default': 'tcp or udp', 'label': 'Packet Filter (BPF)'},
            'analysis_depth': {'type': 'select', 'options': ['headers', 'payload', 'full'], 'default': 'headers', 'label': 'Analysis Depth'}
        },
        'metrics': {
            'packets_analyzed': 0, 
            'threats_detected': 0,
            'bandwidth_usage': 0,
            'suspicious_flows': 0,
            'dpi_accuracy': 99.1
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'scada_ics_security': {
        'name': 'SCADA ICS Security',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/scada_ics_security.sh',
        'args': ['monitor'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/scada_ics_security.log',
        'parameters': {
            'hmi_networks': {'type': 'text', 'default': '10.1.0.0/16', 'label': 'HMI Networks'},
            'plc_range': {'type': 'text', 'default': '10.2.0.0/16', 'label': 'PLC IP Range'},
            'security_level': {'type': 'select', 'options': ['monitoring', 'protection', 'isolation'], 'default': 'monitoring', 'label': 'Security Mode'}
        },
        'metrics': {
            'ics_devices': 0, 
            'security_events': 0,
            'plc_communications': 0,
            'hmi_connections': 0,
            'safety_systems': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    },
    'ssh_hardening': {
        'name': 'SSH Hardening',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/ssh_hardening.sh',
        'args': ['harden'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/ssh_hardening.log',
        'parameters': {
            'ssh_port': {'type': 'number', 'default': '22', 'label': 'SSH Port'},
            'allowed_users': {'type': 'text', 'default': 'admin,security', 'label': 'Allowed Users'},
            'key_algorithm': {'type': 'select', 'options': ['rsa', 'ed25519', 'ecdsa'], 'default': 'ed25519', 'label': 'Key Algorithm'}
        },
        'metrics': {
            'ssh_configs': 0, 
            'hardening_applied': 0,
            'failed_attempts': 0,
            'security_score': 92,
            'keys_managed': 0
        },
        'process': None,
        'status': 'stopped',
        'start_time': None
    }
}

# Routes
@app.route('/')
def index():
    return render_template('dashboard.html', tool_scripts=tool_scripts)

@app.route('/api/tool/<tool_id>/config', methods=['GET', 'POST'])
def tool_config(tool_id):
    """Get or update tool configuration"""
    if tool_id not in tool_scripts:
        return jsonify({'error': 'Tool not found'}), 404
    
    if request.method == 'GET':
        return jsonify({
            'parameters': tool_scripts[tool_id]['parameters'],
            'current_values': {param: config.get('current', config['default']) 
                             for param, config in tool_scripts[tool_id]['parameters'].items()}
        })
    
    if request.method == 'POST':
        data = request.json
        if not data:
            return jsonify({'error': 'No configuration data provided'}), 400
        
        # Validate and update configuration
        updated_config = {}
        for param, value in data.items():
            if param in tool_scripts[tool_id]['parameters']:
                param_config = tool_scripts[tool_id]['parameters'][param]
                
                # Type validation
                if param_config['type'] == 'number':
                    try:
                        value = float(value)
                    except ValueError:
                        return jsonify({'error': f'Invalid number for {param}'}), 400
                elif param_config['type'] == 'checkbox':
                    value = bool(value)
                elif param_config['type'] == 'select':
                    if value not in param_config['options']:
                        return jsonify({'error': f'Invalid option for {param}'}), 400
                
                updated_config[param] = value
                tool_scripts[tool_id]['parameters'][param]['current'] = value
        
        return jsonify({'success': True, 'updated': updated_config})

def build_tool_args(tool_id):
    """Build command line arguments from tool configuration"""
    tool = tool_scripts[tool_id]
    args = list(tool['args'])  # Start with default args
    
    # Add configured parameters
    for param, config in tool['parameters'].items():
        value = config.get('current', config['default'])
        
        # Convert parameter to command line argument
        if param == 'target_ip' or param == 'target_network':
            args.extend(['--target', str(value)])
        elif param == 'scan_type':
            args.extend(['--scan-type', str(value)])
        elif param == 'port_range':
            args.extend(['--ports', str(value)])
        elif param == 'interface' or param == 'monitor_interface' or param == 'capture_interface':
            args.extend(['--interface', str(value)])
        elif param == 'subnet_list' or param == 'subnets':
            args.extend(['--subnets', str(value)])
        elif param == 'protocols':
            args.extend(['--protocols', str(value)])
        elif param == 'service_list':
            args.extend(['--services', str(value)])
        elif param == 'check_interval':
            args.extend(['--interval', str(value)])
        elif param == 'hardening_level' or param == 'security_level':
            args.extend(['--level', str(value)])
        elif param == 'ssh_port':
            args.extend(['--port', str(value)])
        elif param == 'allowed_users':
            args.extend(['--users', str(value)])
        elif config['type'] == 'checkbox' and value:
            args.append(f'--{param.replace("_", "-")}')
    
    return args

@app.route('/api/tool/<tool>/start', methods=['POST'])
def start_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    
    t = tool_scripts[tool]
    if t['process'] and t['process'].poll() is None:
        return jsonify({'status': 'already running'})
    
    try:
        if simulation_mode:
            # Simulation mode - run simulation instead of actual script
            t['status'] = 'running'
            t['start_time'] = datetime.now()
            t['process'] = 'simulation'  # Mark as simulation process
            
            # Get configuration for simulation
            config_params = {}
            for param, config in t['parameters'].items():
                config_params[param] = config.get('current', config['default'])
            
            # Start simulation in background thread
            simulation_thread = threading.Thread(target=simulate_tool_execution, args=(tool,))
            simulation_thread.daemon = True
            simulation_thread.start()
            
            # Emit real-time status update
            socketio.emit('tool_status_update', {
                'tool': tool,
                'status': 'running',
                'running': True,
                'config_args': [f"--{k.replace('_', '-')} {v}" for k, v in config_params.items()],
                'mode': 'simulation'
            })
            
            return jsonify({
                'status': 'started', 
                'mode': 'simulation',
                'config_args': [f"--{k.replace('_', '-')} {v}" for k, v in config_params.items()]
            })
        else:
            # Real mode - execute actual script
            args = build_tool_args(tool)
            
            t['process'] = subprocess.Popen(['bash', t['script']] + args, 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE)
            t['status'] = 'running'
            t['start_time'] = datetime.now()
            
            # Emit real-time status update
            socketio.emit('tool_status_update', {
                'tool': tool,
                'status': 'running',
                'running': True,
                'config_args': args[1:],  # Skip the main command
                'mode': 'real'
            })
            
            return jsonify({'status': 'started', 'config_args': args[1:], 'mode': 'real'})
            
    except Exception as e:
        t['status'] = 'error'
        socketio.emit('tool_status_update', {
            'tool': tool,
            'status': 'error',
            'running': False,
            'error': str(e)
        })
        return jsonify({'error': str(e)}), 500

@app.route('/api/tool/<tool>/stop', methods=['POST'])
def stop_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    
    t = tool_scripts[tool]
    
    if simulation_mode and t['process'] == 'simulation':
        # Stop simulation
        t['process'] = None
        t['status'] = 'stopped'
        
        # Emit real-time status update
        socketio.emit('tool_status_update', {
            'tool': tool,
            'status': 'stopped',
            'running': False,
            'message': 'Simulation stopped'
        })
        
        return jsonify({'status': 'stopped', 'mode': 'simulation'})
    
    elif t['process'] and t['process'].poll() is None:
        # Stop real process
        t['process'].terminate()
        t['status'] = 'stopped'
        
        # Emit real-time status update
        socketio.emit('tool_status_update', {
            'tool': tool,
            'status': 'stopped',
            'running': False
        })
        
        return jsonify({'status': 'stopped'})
    
    return jsonify({'status': 'not running'})
    return jsonify({'status': 'already stopped'})

@app.route('/api/tool/<tool>/status', methods=['GET'])
def status_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    
    t = tool_scripts[tool]
    running = t['process'] and t['process'].poll() is None
    return jsonify({'status': t['status'], 'running': running})

@app.route('/api/tool/<tool>/logs', methods=['GET'])
def logs_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    
    t = tool_scripts[tool]
    log_path = t['log']
    
    try:
        if '*' in log_path:
            log_files = glob.glob(log_path)
            if not log_files:
                return jsonify({'logs': ['No log files found']})
            log_file = sorted(log_files)[-1]
        else:
            if not os.path.exists(log_path):
                return jsonify({'logs': ['Log file not found']})
            log_file = log_path
        
        with open(log_file, 'r') as f:
            lines = f.readlines()[-20:]  # Last 20 lines
        return jsonify({'logs': lines})
    except Exception as e:
        return jsonify({'logs': [f'Error reading logs: {str(e)}']})

@app.route('/api/tool/<tool>/metrics', methods=['GET'])
def metrics_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    
    t = tool_scripts[tool]
    metrics = t['metrics'].copy()
    
    # Calculate uptime if tool is running
    if t['start_time'] and t['status'] == 'running':
        uptime = (datetime.now() - t['start_time']).total_seconds() / 3600
        if 'uptime_hours' in metrics:
            metrics['uptime_hours'] = round(uptime, 2)
    
    return jsonify({'metrics': metrics})

@app.route('/api/system')
def system_stats():
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_connections()
        
        return jsonify({
            'cpu_percent': round(cpu_percent, 1),
            'memory_percent': round(memory.percent, 1),
            'disk_usage': round(disk.percent, 1),
            'network_connections': len(network),
            'memory_total': round(memory.total / (1024**3), 2),  # GB
            'memory_available': round(memory.available / (1024**3), 2),  # GB
            'disk_total': round(disk.total / (1024**3), 2),  # GB
            'disk_free': round(disk.free / (1024**3), 2)  # GB
        })
    except Exception as e:
        return jsonify({
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_usage': 0,
            'network_connections': 0,
            'error': str(e)
        })

@app.route('/api/global_metrics')
def get_global_metrics():
    return jsonify({
        'global_metrics': global_metrics,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/simulation/toggle', methods=['POST'])
def toggle_simulation_mode():
    """Toggle simulation mode on/off"""
    global simulation_mode
    data = request.json
    if data and 'simulation' in data:
        simulation_mode = bool(data['simulation'])
        return jsonify({'simulation': simulation_mode, 'message': f'Simulation mode {"enabled" if simulation_mode else "disabled"}'})
    return jsonify({'error': 'Invalid request'}), 400

@app.route('/api/simulation/status')
def get_simulation_status():
    """Get current simulation mode status"""
    return jsonify({'simulation': simulation_mode})

def simulate_advanced_metrics():
    """Simulate realistic metric updates for tools"""
    for tool_key, tool_config in tool_scripts.items():
        if tool_config['status'] == 'running':
            metrics = tool_config['metrics']
            
            # Simulate metric updates based on tool type
            if tool_key == 'blue_agent':
                metrics['alerts'] += random.randint(0, 3)
                metrics['findings'] += random.randint(0, 2)
                metrics['threats_blocked'] += random.randint(0, 1)
                if random.random() < 0.1:  # 10% chance
                    metrics['remediations'] += 1
                    
            elif tool_key == 'network_traffic_analyzer':
                metrics['packets_analyzed'] += random.randint(100, 1000)
                if random.random() < 0.05:  # 5% chance
                    metrics['threats_detected'] += 1
                    global_metrics['threats_detected'] += 1
                metrics['bandwidth_usage'] = random.randint(10, 95)
                metrics['suspicious_flows'] += random.randint(0, 2)
                
            elif tool_key == 'firewall_hardening':
                metrics['blocked_attempts'] += random.randint(0, 5)
                global_metrics['firewall_blocks'] += random.randint(0, 3)
                if random.random() < 0.3:  # 30% chance
                    metrics['threats_mitigated'] += 1
                    
            elif tool_key == 'energy_vulnerability_scanner':
                if random.random() < 0.2:  # 20% chance
                    metrics['vulnerabilities'] += 1
                    global_metrics['vulnerabilities_found'] += 1
                metrics['energy_devices'] += random.randint(0, 2)
                metrics['scada_systems'] += random.randint(0, 1)
                
            elif tool_key == 'incident_response_playbooks':
                if random.random() < 0.1:  # 10% chance
                    metrics['incidents'] += 1
                    metrics['responses'] += 1
                    global_metrics['incidents_resolved'] += 1
                metrics['avg_response_time'] = random.randint(30, 300)  # seconds
                
            elif tool_key == 'industrial_protocol_monitor':
                metrics['modbus_packets'] += random.randint(0, 50)
                metrics['dnp3_messages'] += random.randint(0, 30)
                metrics['iec_communications'] += random.randint(0, 20)
                if random.random() < 0.05:  # 5% chance
                    metrics['anomalies'] += 1
                    global_metrics['network_anomalies'] += 1
                    
            elif tool_key == 'multi_subnet_scanner':
                metrics['hosts_discovered'] += random.randint(0, 5)
                metrics['open_ports'] += random.randint(0, 10)
                metrics['network_coverage'] = min(100, metrics['network_coverage'] + random.randint(0, 5))
                
            elif tool_key == 'ssh_hardening':
                metrics['failed_attempts'] += random.randint(0, 3)
                global_metrics['failed_logins'] += random.randint(0, 2)
                if random.random() < 0.1:  # 10% chance
                    metrics['keys_managed'] += 1

# Real-time monitoring background thread
def background_monitor():
    """Background thread to monitor tools and emit real-time updates"""
    while True:
        try:
            # Update advanced metrics for running tools
            simulate_advanced_metrics()
            
            # Check tool status and emit updates
            for tool_key, tool_config in tool_scripts.items():
                if tool_config['process']:
                    if simulation_mode and tool_config['process'] == 'simulation':
                        # Simulation mode - process is a string marker
                        running = tool_config['status'] == 'running'
                    elif not simulation_mode and tool_config['process'] != 'simulation':
                        # Real mode - check actual process
                        running = tool_config['process'].poll() is None
                        if not running and tool_config['status'] == 'running':
                            tool_config['status'] = 'stopped'
                            tool_config['process'] = None
                    else:
                        continue  # Skip if mode mismatch
                    
                    # Emit status updates only on changes
                    if running != (tool_config['status'] == 'running'):
                        tool_config['status'] = 'running' if running else 'stopped'
                        socketio.emit('tool_status_update', {
                            'tool': tool_key,
                            'status': tool_config['status'],
                            'running': running
                        })
                
                # Emit metric updates for running tools
                if tool_config['status'] == 'running':
                    metrics = tool_config['metrics'].copy()
                    
                    # Calculate uptime
                    if tool_config['start_time']:
                        uptime = (datetime.now() - tool_config['start_time']).total_seconds() / 3600
                        if 'uptime_hours' in metrics:
                            metrics['uptime_hours'] = round(uptime, 2)
                    
                    socketio.emit('tool_metrics_update', {
                        'tool': tool_key,
                        'metrics': metrics
                    })
                
                # Emit log updates
                try:
                    log_path = tool_config['log']
                    if '*' in log_path:
                        log_files = glob.glob(log_path)
                        if log_files:
                            log_file = sorted(log_files)[-1]
                        else:
                            continue
                    else:
                        if not os.path.exists(log_path):
                            continue
                        log_file = log_path
                    
                    with open(log_file, 'r') as f:
                        lines = f.readlines()[-10:]  # Last 10 lines
                    
                    socketio.emit('tool_logs_update', {
                        'tool': tool_key,
                        'logs': lines
                    })
                except Exception:
                    pass  # Ignore log reading errors
            
            # Emit system stats
            try:
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                network = psutil.net_connections()
                
                socketio.emit('system_stats_update', {
                    'cpu_percent': round(cpu_percent, 1),
                    'memory_percent': round(memory.percent, 1),
                    'disk_usage': round(disk.percent, 1),
                    'network_connections': len(network)
                })
            except Exception:
                pass
            
            # Emit global security metrics
            socketio.emit('global_metrics_update', {
                'global_metrics': global_metrics,
                'timestamp': datetime.now().isoformat()
            })
            
            time.sleep(3)  # Update every 3 seconds for more responsive metrics
        except Exception as e:
            print(f"Background monitor error: {e}")
            time.sleep(5)

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    # Send initial status for all tools
    for tool_key, tool_config in tool_scripts.items():
        running = tool_config['process'] and tool_config['process'].poll() is None
        emit('tool_status_update', {
            'tool': tool_key,
            'status': tool_config['status'],
            'running': running
        })

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    print("Starting CEG25 Blue Team Dashboard with Real-time Updates on http://localhost:5000")
    os.makedirs('/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs', exist_ok=True)
    
    # Start background monitoring thread
    monitor_thread = threading.Thread(target=background_monitor, daemon=True)
    monitor_thread.start()
    
    # Run with SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)