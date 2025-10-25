#!/usr/bin/env python3

# ============================================================================
# Blue Team Monitoring Dashboard for CEG25 Competition
# ============================================================================
# Real-time web interface for energy infrastructure defense monitoring
# Integrated monitoring of all Blue Team tools and services
# ============================================================================

import os
import sys
import json
import time
import psutil
import socket
import threading
import subprocess
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO, emit
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/dashboard.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ceg25-blue-team-dashboard-2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Dashboard configuration
DASHBOARD_CONFIG = {
    'version': '1.0',
    'competition': 'CEG25',
    'location': 'Warsaw, Poland',
    'dates': 'October 28-30, 2025',
    'team': 'Blue Team - Energy Infrastructure Defense'
}

# System monitoring data
system_stats = {
    'cpu_percent': 0,
    'memory_percent': 0,
    'disk_usage': 0,
    'network_connections': 0,
    'uptime': 0
}

# Service monitoring data
service_status = {
    'scada-master': {'status': 'unknown', 'last_check': None, 'uptime': 0, 'restarts': 0},
    'plc-controller-01': {'status': 'unknown', 'last_check': None, 'uptime': 0, 'restarts': 0},
    'hmi-interface': {'status': 'unknown', 'last_check': None, 'uptime': 0, 'restarts': 0},
    'energy-database': {'status': 'unknown', 'last_check': None, 'uptime': 0, 'restarts': 0},
    'modbus-gateway': {'status': 'unknown', 'last_check': None, 'uptime': 0, 'restarts': 0},
    'dnp3-server': {'status': 'unknown', 'last_check': None, 'uptime': 0, 'restarts': 0},
    'iec61850-service': {'status': 'unknown', 'last_check': None, 'uptime': 0, 'restarts': 0},
    'monitoring-agent': {'status': 'unknown', 'last_check': None, 'uptime': 0, 'restarts': 0}
}

# Incident tracking
active_incidents = []
incident_history = []

# Network traffic data
traffic_stats = {
    'packets_captured': 0,
    'attacks_detected': 0,
    'protocols_detected': [],
    'last_capture': None
}

# Competition scoring
competition_score = {
    'response_time': 0,
    'containment': 0,
    'recovery': 0,
    'forensics': 0,
    'reporting': 0,
    'total_score': 0,
    'rank': 'N/A'
}

# Background monitoring thread
monitoring_thread = None
monitoring_active = False

tool_scripts = {
    'blue_agent': {
        'name': 'Blue Agent',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/blue_agent.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/blue_agent.log',
        'metrics': {'alerts': 0, 'findings': 0, 'remediations': 0},
        'process': None,
        'status': 'stopped'
    },
    'ceg25_competition': {
        'name': 'CEG25 Competition',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/ceg25_competition.sh',
        'args': ['run'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/ceg25/*.log',
        'metrics': {'phases': 0, 'actions': 0},
        'process': None,
        'status': 'stopped'
    },
    'docker_security': {
        'name': 'Docker Security',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/docker_security.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/docker_security/*.log',
        'metrics': {'containers': 0, 'issues': 0},
        'process': None,
        'status': 'stopped'
    },
    'firewall_hardening': {
        'name': 'Firewall Hardening',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/firewall_hardening.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/firewall_hardening/*.log',
        'metrics': {'rules': 0, 'alerts': 0},
        'process': None,
        'status': 'stopped'
    },
    'incident_response': {
        'name': 'Incident Response',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/incident_response_playbooks.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/incident_response/*.log',
        'metrics': {'incidents': 0, 'critical': 0, 'high': 0},
        'process': None,
        'status': 'stopped'
    },
    'network_traffic': {
        'name': 'Network Traffic Analyzer',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/network_traffic_analyzer.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/network_traffic/*.log',
        'metrics': {'alerts': 0, 'protocols': 0},
        'process': None,
        'status': 'stopped'
    },
    'multi_subnet_scanner': {
        'name': 'Multi-Subnet Scanner',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/multi_subnet_scanner.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/network/multi_subnet_*.log',
        'metrics': {'subnets': 0, 'hosts': 0},
        'process': None,
        'status': 'stopped'
    },
    'ssh_hardening': {
        'name': 'SSH Hardening',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/ssh_hardening.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/ssh_hardening/*.log',
        'metrics': {'changes': 0, 'alerts': 0},
        'process': None,
        'status': 'stopped'
    },
    'automated_service_restoration': {
        'name': 'Service Restoration',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/automated_service_restoration.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/service_restoration/*.log',
        'metrics': {'services': 0, 'actions': 0},
        'process': None,
        'status': 'stopped'
    },
    'energy_vuln': {
        'name': 'Energy Vulnerability Scanner',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/energy_vulnerability_scanner.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/energy_vulns/*.log',
        'metrics': {'active_scans': 0, 'critical_vulns': 0, 'high_vulns': 0, 'medium_vulns': 0},
        'process': None,
        'status': 'stopped'
    },
    'protocol_monitor': {
        'name': 'Industrial Protocol Monitor',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/industrial_protocol_monitor.sh',
        'args': ['start'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/protocol_monitor/*.log',
        'metrics': {'connections': 0, 'alerts': 0, 'protocols': 0},
        'process': None,
        'status': 'stopped'
    },
    'scada_scan': {
        'name': 'SCADA/ICS Security Scanner',
        'script': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/linux/scada_ics_security.sh',
        'args': ['scan'],
        'log': '/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs/scada/*.log',
        'metrics': {'devices_found': 0, 'vulns_found': 0, 'protocols_scanned': 0},
        'process': None,
        'status': 'stopped'
    }
}

def get_system_stats():
    """Get current system statistics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_connections = len(psutil.net_connections())

        # Calculate uptime
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        uptime_str = str(timedelta(seconds=int(uptime_seconds)))

        system_stats.update({
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_usage': disk.percent,
            'network_connections': net_connections,
            'uptime': uptime_str
        })

        return system_stats
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return system_stats

def check_service_status():
    """Check status of critical services"""
    for service_name in service_status.keys():
        try:
            # Simulate service checking (in real implementation, check actual services)
            import random
            status = 'healthy' if random.random() > 0.1 else 'down'

            service_status[service_name].update({
                'status': status,
                'last_check': datetime.now().isoformat(),
                'uptime': service_status[service_name]['uptime'] + 1 if status == 'healthy' else 0
            })
        except Exception as e:
            logger.error(f"Error checking service {service_name}: {e}")
            service_status[service_name]['status'] = 'error'

def load_incident_data():
    """Load incident data from log files"""
    try:
        incident_log = '../logs/incident_response/incident_response_*.log'
        # In real implementation, parse actual log files
        # For demo, simulate some incidents
        if len(active_incidents) == 0:
            active_incidents.extend([
                {
                    'id': 'INC-001',
                    'type': 'SCADA_ATTACK',
                    'severity': 'HIGH',
                    'status': 'INVESTIGATING',
                    'timestamp': datetime.now().isoformat(),
                    'description': 'Unauthorized Modbus write command detected'
                },
                {
                    'id': 'INC-002',
                    'type': 'NETWORK_INTRUSION',
                    'severity': 'MEDIUM',
                    'status': 'CONTAINED',
                    'timestamp': (datetime.now() - timedelta(minutes=15)).isoformat(),
                    'description': 'Suspicious lateral movement detected'
                }
            ])
    except Exception as e:
        logger.error(f"Error loading incident data: {e}")

def load_traffic_data():
    """Load network traffic analysis data"""
    try:
        # In real implementation, read from traffic analysis logs
        traffic_stats.update({
            'packets_captured': 15420,
            'attacks_detected': 3,
            'protocols_detected': ['MODBUS', 'DNP3', 'HTTP', 'SSH'],
            'last_capture': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error loading traffic data: {e}")

def calculate_competition_score():
    """Calculate current competition score"""
    try:
        # Simulate scoring calculation
        import random
        competition_score.update({
            'response_time': random.randint(25, 30),
            'containment': random.randint(20, 25),
            'recovery': random.randint(15, 20),
            'forensics': random.randint(10, 15),
            'reporting': random.randint(8, 10),
        })

        # Calculate total
        total = sum(competition_score.values()) - competition_score['total_score']  # Exclude old total
        competition_score['total_score'] = total

        # Determine rank (simplified)
        if total >= 90:
            competition_score['rank'] = '1st Place'
        elif total >= 80:
            competition_score['rank'] = '2nd Place'
        elif total >= 70:
            competition_score['rank'] = '3rd Place'
        else:
            competition_score['rank'] = 'Needs Improvement'

    except Exception as e:
        logger.error(f"Error calculating competition score: {e}")

def monitoring_worker():
    """Background monitoring worker"""
    global monitoring_active
    monitoring_active = True

    logger.info("Starting background monitoring")

    while monitoring_active:
        try:
            # Update system stats
            get_system_stats()

            # Check service status
            check_service_status()

            # Load incident data
            load_incident_data()

            # Load traffic data
            load_traffic_data()

            # Calculate competition score
            calculate_competition_score()

            # Emit updates via WebSocket
            socketio.emit('system_update', system_stats)
            socketio.emit('services_update', service_status)
            socketio.emit('incidents_update', {
                'active': active_incidents,
                'history': incident_history[-10:]  # Last 10 incidents
            })
            socketio.emit('traffic_update', traffic_stats)
            socketio.emit('score_update', competition_score)

            # Wait before next update
            socketio.sleep(5)  # Update every 5 seconds

        except Exception as e:
            logger.error(f"Error in monitoring worker: {e}")
            socketio.sleep(5)

    logger.info("Background monitoring stopped")

# Flask routes
# Per-tool metrics API
@app.route('/api/tool/<tool>/metrics', methods=['GET'])
def metrics_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    t = tool_scripts[tool]
    # Parse metrics from log file (simple demo)
    import glob
    log_files = glob.glob(t['log'])
    test_log_dir = os.path.dirname(t['log'].replace('*',''))
    test_logs = glob.glob(os.path.join(test_log_dir, '*_test.log'))
    all_logs = log_files + test_logs
    if not all_logs:
        return jsonify({'metrics': t['metrics']})
    lines = []
    for log_file in all_logs:
        try:
            with open(log_file, 'r') as f:
                lines.extend(f.readlines())
        except Exception:
            continue
    metrics = dict(t['metrics'])
    # Per-tool metrics parsing
    if tool == 'blue_agent':
        metrics['alerts'] = sum('ALERT' in l for l in lines)
        metrics['findings'] = sum('FINDING' in l for l in lines)
        metrics['remediations'] = sum('REMEDIATION' in l for l in lines)
    elif tool == 'ceg25_competition':
        metrics['phases'] = sum('Phase:' in l for l in lines)
        metrics['actions'] = sum('ACTION' in l for l in lines)
    elif tool == 'docker_security':
        metrics['containers'] = sum('container' in l.lower() for l in lines)
        metrics['issues'] = sum('ISSUE' in l for l in lines)
    elif tool == 'firewall_hardening':
        metrics['rules'] = sum('RULE' in l for l in lines)
        metrics['alerts'] = sum('ALERT' in l for l in lines)
    elif tool == 'incident_response':
        metrics['incidents'] = sum('INCIDENT' in l for l in lines)
        metrics['critical'] = sum('CRITICAL' in l for l in lines)
        metrics['high'] = sum('HIGH' in l for l in lines)
    elif tool == 'network_traffic':
        metrics['alerts'] = sum('ALERT' in l for l in lines)
        metrics['protocols'] = sum('protocol' in l.lower() for l in lines)
    elif tool == 'multi_subnet_scanner':
        metrics['subnets'] = sum('Subnet:' in l for l in lines)
        metrics['hosts'] = sum('Host:' in l for l in lines)
    elif tool == 'ssh_hardening':
        metrics['changes'] = sum('CHANGE' in l for l in lines)
        metrics['alerts'] = sum('ALERT' in l for l in lines)
    elif tool == 'automated_service_restoration':
        metrics['services'] = sum('Service:' in l for l in lines)
        metrics['actions'] = sum('ACTION' in l for l in lines)
    elif tool == 'energy_vuln':
        metrics['active_scans'] = sum('assessment' in l for l in lines)
        metrics['critical_vulns'] = sum('[CRITICAL]' in l for l in lines)
        metrics['high_vulns'] = sum('[VULN]' in l for l in lines)
        metrics['medium_vulns'] = sum('[WARN]' in l for l in lines)
    elif tool == 'protocol_monitor':
        metrics['connections'] = sum('communication' in l for l in lines)
        metrics['alerts'] = sum('ALERT' in l for l in lines)
        metrics['protocols'] = sum('protocol signature' in l for l in lines)
    elif tool == 'scada_scan':
        metrics['devices_found'] = sum('device found' in l for l in lines)
        metrics['vulns_found'] = sum('VULNERABLE' in l for l in lines)
        metrics['protocols_scanned'] = sum('Scanning for' in l for l in lines)
    return jsonify({'metrics': metrics})
# ...existing code...

# Per-tool control API
@app.route('/api/tool/<tool>/start', methods=['POST'])
def start_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    t = tool_scripts[tool]
    if t['process'] and t['process'].poll() is None:
        return jsonify({'status': 'already running'})
    try:
        t['process'] = subprocess.Popen(['bash', t['script']] + t['args'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t['status'] = 'running'
        return jsonify({'status': 'started'})
    except Exception as e:
        t['status'] = 'error'
        return jsonify({'error': str(e)}), 500

@app.route('/api/tool/<tool>/stop', methods=['POST'])
def stop_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    t = tool_scripts[tool]
    if t['process'] and t['process'].poll() is None:
        t['process'].terminate()
        t['status'] = 'stopped'
        return jsonify({'status': 'stopped'})
    t['status'] = 'stopped'
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
    import glob
    
    # Handle both direct file paths and glob patterns
    log_path = t['log']
    if '*' in log_path:
        log_files = glob.glob(log_path)
        if not log_files:
            return jsonify({'logs': ['No log files found']})
        log_file = sorted(log_files)[-1]  # Get newest file
    else:
        # Direct file path
        if not os.path.exists(log_path):
            return jsonify({'logs': ['Log file not found']})
        log_file = log_path
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()[-50:]  # Get last 50 lines
        return jsonify({'logs': lines})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html', config=DASHBOARD_CONFIG, tool_scripts=tool_scripts)

@app.route('/api/system')
def get_system():
    """Get system statistics"""
    return jsonify(system_stats)

@app.route('/api/services')
def get_services():
    """Get service status"""
    return jsonify(service_status)

@app.route('/api/incidents')
def get_incidents():
    """Get incident data"""
    return jsonify({
        'active': active_incidents,
        'history': incident_history
    })

@app.route('/api/traffic')
def get_traffic():
    """Get traffic analysis data"""
    return jsonify(traffic_stats)

@app.route('/api/score')
def get_score():
    """Get competition score"""
    return jsonify(competition_score)

@app.route('/api/logs/<log_type>')
def get_logs(log_type):
    """Get log data"""
    try:
        if log_type == 'system':
            log_file = '../logs/dashboard.log'
        elif log_type == 'incidents':
            log_file = '../logs/incident_response/incident_response_*.log'
        elif log_type == 'traffic':
            log_file = '../logs/network_traffic/network_traffic_*.log'
        else:
            return jsonify({'error': 'Invalid log type'}), 400

        # Read log file (simplified)
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()[-50:]  # Last 50 lines
            return jsonify({'logs': lines})
        else:
            return jsonify({'logs': ['Log file not found']})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebSocket events
# ...existing code...

# Per-tool WebSocket events
@socketio.on('start_tool')
def ws_start_tool(data):
    tool = data.get('tool')
    if tool not in tool_scripts:
        emit('tool_status', {'tool': tool, 'status': 'error', 'message': 'Unknown tool'})
        return
    t = tool_scripts[tool]
    if t['process'] and t['process'].poll() is None:
        emit('tool_status', {'tool': tool, 'status': 'already running'})
        return
    try:
        t['process'] = subprocess.Popen(['bash', t['script']] + t['args'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        t['status'] = 'running'
        emit('tool_status', {'tool': tool, 'status': 'started'})
    except Exception as e:
        t['status'] = 'error'
        emit('tool_status', {'tool': tool, 'status': 'error', 'message': str(e)})

@socketio.on('stop_tool')
def ws_stop_tool(data):
    tool = data.get('tool')
    if tool not in tool_scripts:
        emit('tool_status', {'tool': tool, 'status': 'error', 'message': 'Unknown tool'})
        return
    t = tool_scripts[tool]
    if t['process'] and t['process'].poll() is None:
        t['process'].terminate()
        t['status'] = 'stopped'
        emit('tool_status', {'tool': tool, 'status': 'stopped'})
        return
    t['status'] = 'stopped'
    emit('tool_status', {'tool': tool, 'status': 'already stopped'})

@socketio.on('tool_status')
def ws_status_tool(data):
    tool = data.get('tool')
    if tool not in tool_scripts:
        emit('tool_status', {'tool': tool, 'status': 'error', 'message': 'Unknown tool'})
        return
    t = tool_scripts[tool]
    running = t['process'] and t['process'].poll() is None
    emit('tool_status', {'tool': tool, 'status': t['status'], 'running': running})

@socketio.on('tool_logs')
def ws_logs_tool(data):
    tool = data.get('tool')
    if tool not in tool_scripts:
        emit('tool_logs', {'tool': tool, 'logs': ['Unknown tool']})
        return
    t = tool_scripts[tool]
    import glob
    log_files = glob.glob(t['log'])
    if not log_files:
        emit('tool_logs', {'tool': tool, 'logs': ['Log file not found']})
        return
    log_file = sorted(log_files)[-1]
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()[-50:]
        emit('tool_logs', {'tool': tool, 'logs': lines})
    except Exception as e:
        emit('tool_logs', {'tool': tool, 'logs': [str(e)]})
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected")
    emit('status', {'message': 'Connected to CEG25 Blue Team Dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected")

@socketio.on('start_monitoring')
def handle_start_monitoring():
    """Start background monitoring"""
    global monitoring_thread
    if monitoring_thread is None or not monitoring_thread.is_alive():
        monitoring_thread = socketio.start_background_task(monitoring_worker)
        emit('monitoring_status', {'active': True})
    else:
        emit('monitoring_status', {'active': True, 'message': 'Already running'})

@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    """Stop background monitoring"""
    global monitoring_active
    monitoring_active = False
    emit('monitoring_status', {'active': False})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Template directory setup
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
if not os.path.exists(template_dir):
    os.makedirs(template_dir)

# Create HTML template
dashboard_html = """
        <div class="container mt-4">
            <h2 class="mb-4">Blue Team Toolkit Dashboard</h2>
            <ul class="nav nav-tabs" id="toolTabs" role="tablist">
                {% for key, tool in tool_scripts.items() %}
                <li class="nav-item" role="presentation">
                    <button class="nav-link {% if loop.first %}active{% endif %}" id="{{key}}-tab" data-bs-toggle="tab" data-bs-target="#{{key}}" type="button" role="tab" aria-controls="{{key}}" aria-selected="{% if loop.first %}true{% else %}false{% endif %}">{{tool['name']}}</button>
                </li>
                {% endfor %}
            </ul>
            <div class="tab-content" id="toolTabsContent">
                {% for key, tool in tool_scripts.items() %}
                <div class="tab-pane fade {% if loop.first %}show active{% endif %}" id="{{key}}" role="tabpanel" aria-labelledby="{{key}}-tab">
                    <div class="card mt-3">
                        <div class="card-header">{{tool['name']}}</div>
                        <div class="card-body">
                            <button id="start-{{key}}" class="btn btn-success btn-sm me-2"><i class="fas fa-play"></i> Start</button>
                            <button id="stop-{{key}}" class="btn btn-danger btn-sm me-2"><i class="fas fa-stop"></i> Stop</button>
                            <span id="status-{{key}}" class="badge bg-secondary">Stopped</span>
                            <div class="mt-3 mb-2">
                                <div class="row text-center">
                                    {% for metric, value in tool['metrics'].items() %}
                                    <div class="col"><span id="metric-{{key}}-{{metric}}" class="metric-value">0</span><br><small>{{metric.replace('_',' ').title()}}</small></div>
                                    {% endfor %}
                                </div>
                            </div>
                            <div class="mt-3">
                                <h6>Live Log</h6>
                                <pre id="log-{{key}}" style="background:#222;color:#0f0;height:150px;overflow-y:scroll;padding:8px;border-radius:6px;"></pre>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CEG25 Blue Team Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #1a1a1a; color: #ffffff; }
        .card { background-color: #2d2d2d; border: 1px solid #444; margin-bottom: 20px; }
        .card-header { background-color: #333; border-bottom: 1px solid #444; }
        .status-healthy { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-danger { color: #dc3545; }
        .status-unknown { color: #6c757d; }
        .metric-value { font-size: 2rem; font-weight: bold; }
        .competition-header { background: linear-gradient(45deg, #007bff, #28a745); color: white; }
        .incident-critical { background-color: #dc3545; color: white; }
        .incident-high { background-color: #fd7e14; color: white; }
        .incident-medium { background-color: #ffc107; color: black; }
        .incident-low { background-color: #28a745; color: white; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Header -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card competition-header">
                    <div class="card-header">
                        <h1 class="mb-0"><i class="fas fa-shield-alt"></i> CEG25 Blue Team Dashboard</h1>
                        <p class="mb-0">Energy Infrastructure Defense | Warsaw, Poland | October 28-30, 2025</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Per-Tool Control Panel -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-cogs"></i> Blue Team Toolkit Controls</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <!-- Energy Vulnerability Scanner -->
                            <div class="col-md-4 mb-3">
                                <div class="card">
                                    <div class="card-header">Energy Vulnerability Scanner</div>
                                    <div class="card-body">
                                        <button id="startEnergyVuln" class="btn btn-success btn-sm me-2"><i class="fas fa-play"></i> Start</button>
                                        <button id="stopEnergyVuln" class="btn btn-danger btn-sm me-2"><i class="fas fa-stop"></i> Stop</button>
                                        <span id="statusEnergyVuln" class="badge bg-secondary">Stopped</span>
                                        <div class="mt-3 mb-2">
                                            <div class="row text-center">
                                                <div class="col-4"><span id="energyActiveScans" class="metric-value">0</span><br><small>Active Scans</small></div>
                                                <div class="col-4"><span id="energyCriticalVulns" class="metric-value text-danger">0</span><br><small>Critical Vulns</small></div>
                                                <div class="col-4"><span id="energyHighVulns" class="metric-value text-warning">0</span><br><small>High Vulns</small></div>
                                            </div>
                                            <div class="row text-center mt-2">
                                                <div class="col-12"><span id="energyMediumVulns" class="metric-value text-info">0</span><br><small>Medium Vulns</small></div>
                                            </div>
                                        </div>
                                        <div class="mt-3">
                                            <h6>Live Log</h6>
                                            <pre id="logEnergyVuln" style="background:#222;color:#0f0;height:150px;overflow-y:scroll;padding:8px;border-radius:6px;"></pre>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <!-- Protocol Monitor -->
                            <div class="col-md-4 mb-3">
                                <div class="card">
                                    <div class="card-header">Industrial Protocol Monitor</div>
                                    <div class="card-body">
                                        <button id="startProtocolMonitor" class="btn btn-success btn-sm me-2"><i class="fas fa-play"></i> Start</button>
                                        <button id="stopProtocolMonitor" class="btn btn-danger btn-sm me-2"><i class="fas fa-stop"></i> Stop</button>
                                        <span id="statusProtocolMonitor" class="badge bg-secondary">Stopped</span>
                                        <div class="mt-3 mb-2">
                                            <div class="row text-center">
                                                <div class="col-4"><span id="protocolConnections" class="metric-value">0</span><br><small>Connections</small></div>
                                                <div class="col-4"><span id="protocolAlerts" class="metric-value text-danger">0</span><br><small>Alerts</small></div>
                                                <div class="col-4"><span id="protocolProtocols" class="metric-value text-info">0</span><br><small>Protocols</small></div>
                                            </div>
                                        </div>
                                        <div class="mt-3">
                                            <h6>Live Log</h6>
                                            <pre id="logProtocolMonitor" style="background:#222;color:#0f0;height:150px;overflow-y:scroll;padding:8px;border-radius:6px;"></pre>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <!-- SCADA/ICS Security Scanner -->
                            <div class="col-md-4 mb-3">
                                <div class="card">
                                    <div class="card-header">SCADA/ICS Security Scanner</div>
                                    <div class="card-body">
                                        <button id="startScadaScan" class="btn btn-success btn-sm me-2"><i class="fas fa-play"></i> Start</button>
                                        <button id="stopScadaScan" class="btn btn-danger btn-sm me-2"><i class="fas fa-stop"></i> Stop</button>
                                        <span id="statusScadaScan" class="badge bg-secondary">Stopped</span>
                                        <div class="mt-3 mb-2">
                                            <div class="row text-center">
                                                <div class="col-4"><span id="scadaDevicesFound" class="metric-value">0</span><br><small>Devices Found</small></div>
                                                <div class="col-4"><span id="scadaVulnsFound" class="metric-value text-danger">0</span><br><small>Vulns Found</small></div>
                                                <div class="col-4"><span id="scadaProtocolsScanned" class="metric-value text-info">0</span><br><small>Protocols Scanned</small></div>
                                            </div>
                                        </div>
                                        <div class="mt-3">
                                            <h6>Live Log</h6>
                                            <pre id="logScadaScan" style="background:#222;color:#0f0;height:150px;overflow-y:scroll;padding:8px;border-radius:6px;"></pre>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- System Overview -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <i class="fas fa-microchip fa-2x mb-2"></i>
                        <h6>CPU Usage</h6>
                        <div class="metric-value" id="cpuPercent">0%</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <i class="fas fa-memory fa-2x mb-2"></i>
                        <h6>Memory Usage</h6>
                        <div class="metric-value" id="memoryPercent">0%</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <i class="fas fa-hdd fa-2x mb-2"></i>
                        <h6>Disk Usage</h6>
                        <div class="metric-value" id="diskPercent">0%</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <i class="fas fa-network-wired fa-2x mb-2"></i>
                        <h6>Network Connections</h6>
                        <div class="metric-value" id="networkConnections">0</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Competition Score -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-trophy"></i> Competition Score</h5>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-md-2">
                                <div class="metric-value text-primary" id="responseTime">0</div>
                                <small>Response Time</small>
                            </div>
                            <div class="col-md-2">
                                <div class="metric-value text-success" id="containment">0</div>
                                <small>Containment</small>
                            </div>
                            <div class="col-md-2">
                                <div class="metric-value text-info" id="recovery">0</div>
                                <small>Recovery</small>
                            </div>
                            <div class="col-md-2">
                                <div class="metric-value text-warning" id="forensics">0</div>
                                <small>Forensics</small>
                            </div>
                            <div class="col-md-2">
                                <div class="metric-value text-secondary" id="reporting">0</div>
                                <small>Reporting</small>
                            </div>
                            <div class="col-md-2">
                                <div class="metric-value text-danger" id="totalScore">0</div>
                                <small>Total Score</small>
                            </div>
                        </div>
                        <div class="text-center mt-3">
                            <h4 id="rank">Rank: N/A</h4>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Services and Incidents -->
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-server"></i> Critical Services</h5>
                    </div>
                    <div class="card-body">
                        <div id="servicesList">
                            <!-- Services will be populated by JavaScript -->
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-exclamation-triangle"></i> Active Incidents</h5>
                    </div>
                    <div class="card-body">
                        <div id="incidentsList">
                            <!-- Incidents will be populated by JavaScript -->
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Network Traffic -->
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-network-wired"></i> Network Traffic Analysis</h5>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-md-3">
                                <div class="metric-value" id="packetsCaptured">0</div>
                                <small>Packets Captured</small>
                            </div>
                            <div class="col-md-3">
                                <div class="metric-value text-danger" id="attacksDetected">0</div>
                                <small>Attacks Detected</small>
                            </div>
                            <div class="col-md-3">
                                <div class="metric-value" id="protocolsCount">0</div>
                                <small>Protocols Detected</small>
                            </div>
                            <div class="col-md-3">
                                <small>Last Capture</small>
                                <div id="lastCapture">Never</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Per-tool metrics DOM elements
        const energyActiveScans = document.getElementById('energyActiveScans');
        const energyCriticalVulns = document.getElementById('energyCriticalVulns');
        const energyHighVulns = document.getElementById('energyHighVulns');
        const energyMediumVulns = document.getElementById('energyMediumVulns');

        const protocolConnections = document.getElementById('protocolConnections');
        const protocolAlerts = document.getElementById('protocolAlerts');
        const protocolProtocols = document.getElementById('protocolProtocols');

        const scadaDevicesFound = document.getElementById('scadaDevicesFound');
        const scadaVulnsFound = document.getElementById('scadaVulnsFound');
        const scadaProtocolsScanned = document.getElementById('scadaProtocolsScanned');

        // Poll metrics every 3 seconds
        function updateMetrics(tool, domMap) {
            fetch(`/api/tool/${tool}/metrics`).then(r => r.json()).then(data => {
                const m = data.metrics || {};
                Object.keys(domMap).forEach(k => {
                    domMap[k].textContent = m[k] !== undefined ? m[k] : '0';
                });
            });
        }
        setInterval(() => {
            updateMetrics('energy_vuln', {
                'active_scans': energyActiveScans,
                'critical_vulns': energyCriticalVulns,
                'high_vulns': energyHighVulns,
                'medium_vulns': energyMediumVulns
            });
            updateMetrics('protocol_monitor', {
                'connections': protocolConnections,
                'alerts': protocolAlerts,
                'protocols': protocolProtocols
            });
            updateMetrics('scada_scan', {
                'devices_found': scadaDevicesFound,
                'vulns_found': scadaVulnsFound,
                'protocols_scanned': scadaProtocolsScanned
            });
        }, 3000);
        const socket = io();

        // Per-tool DOM elements
        const startEnergyVuln = document.getElementById('startEnergyVuln');
        const stopEnergyVuln = document.getElementById('stopEnergyVuln');
        const statusEnergyVuln = document.getElementById('statusEnergyVuln');
        const logEnergyVuln = document.getElementById('logEnergyVuln');

        const startProtocolMonitor = document.getElementById('startProtocolMonitor');
        const stopProtocolMonitor = document.getElementById('stopProtocolMonitor');
        const statusProtocolMonitor = document.getElementById('statusProtocolMonitor');
        const logProtocolMonitor = document.getElementById('logProtocolMonitor');

        const startScadaScan = document.getElementById('startScadaScan');
        const stopScadaScan = document.getElementById('stopScadaScan');
        const statusScadaScan = document.getElementById('statusScadaScan');
        const logScadaScan = document.getElementById('logScadaScan');

        // Per-tool button handlers
        startEnergyVuln.onclick = () => { socket.emit('start_tool', {tool: 'energy_vuln'}); };
        stopEnergyVuln.onclick = () => { socket.emit('stop_tool', {tool: 'energy_vuln'}); };
        startProtocolMonitor.onclick = () => { socket.emit('start_tool', {tool: 'protocol_monitor'}); };
        stopProtocolMonitor.onclick = () => { socket.emit('stop_tool', {tool: 'protocol_monitor'}); };
        startScadaScan.onclick = () => { socket.emit('start_tool', {tool: 'scada_scan'}); };
        stopScadaScan.onclick = () => { socket.emit('stop_tool', {tool: 'scada_scan'}); };

        // Per-tool status updates
        socket.on('tool_status', function(data) {
            if (data.tool === 'energy_vuln') {
                statusEnergyVuln.className = data.status === 'started' || data.status === 'running' ? 'badge bg-success' : 'badge bg-secondary';
                statusEnergyVuln.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);
            }
            if (data.tool === 'protocol_monitor') {
                statusProtocolMonitor.className = data.status === 'started' || data.status === 'running' ? 'badge bg-success' : 'badge bg-secondary';
                statusProtocolMonitor.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);
            }
            if (data.tool === 'scada_scan') {
                statusScadaScan.className = data.status === 'started' || data.status === 'running' ? 'badge bg-success' : 'badge bg-secondary';
                statusScadaScan.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);
            }
        });

        // Per-tool log streaming
        function requestLogs(tool, logElem) {
            socket.emit('tool_logs', {tool: tool});
        }
        socket.on('tool_logs', function(data) {
            if (data.tool === 'energy_vuln') {
                logEnergyVuln.textContent = (data.logs || []).join('');
                logEnergyVuln.scrollTop = logEnergyVuln.scrollHeight;
            }
            if (data.tool === 'protocol_monitor') {
                logProtocolMonitor.textContent = (data.logs || []).join('');
                logProtocolMonitor.scrollTop = logProtocolMonitor.scrollHeight;
            }
            if (data.tool === 'scada_scan') {
                logScadaScan.textContent = (data.logs || []).join('');
                logScadaScan.scrollTop = logScadaScan.scrollHeight;
            }
        });

        // Poll logs every 3 seconds
        setInterval(() => {
            requestLogs('energy_vuln', logEnergyVuln);
            requestLogs('protocol_monitor', logProtocolMonitor);
            requestLogs('scada_scan', logScadaScan);
        }, 3000);

        // ...existing system/score/incident/traffic JS code...
    </script>
</body>
</html>
"""

# Write the HTML template
# Note: Commented out to preserve manually created template
# with open(os.path.join(template_dir, 'dashboard.html'), 'w') as f:
#     f.write(dashboard_html)

def main():
    """Main application entry point"""
    try:
        logger.info("Starting CEG25 Blue Team Dashboard")

        # Create necessary directories
        os.makedirs('/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs', exist_ok=True)
        os.makedirs('/home/goodlife/Desktop/CEG25/blue-team-toolkit/reports', exist_ok=True)
        os.makedirs('/home/goodlife/Desktop/CEG25/blue-team-toolkit/config', exist_ok=True)

        # Start the Flask application
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)

    except KeyboardInterrupt:
        logger.info("Dashboard shutdown requested")
    except Exception as e:
        logger.error(f"Error starting dashboard: {e}")
        sys.exit(1)
    finally:
        global monitoring_active
        monitoring_active = False

if __name__ == '__main__':
    main()