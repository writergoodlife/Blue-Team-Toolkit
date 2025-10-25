#!/usr/bin/env python3

import os
import sys
import json
import glob
import subprocess
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

# Simple Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ceg25-dashboard'
socketio = SocketIO(app, cors_allowed_origins="*")

# Tool configurations with absolute paths
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
    }
}

# Routes
@app.route('/')
def index():
    return render_template('dashboard.html', tool_scripts=tool_scripts)

@app.route('/api/tool/<tool>/start', methods=['POST'])
def start_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    
    t = tool_scripts[tool]
    if t['process'] and t['process'].poll() is None:
        return jsonify({'status': 'already running'})
    
    try:
        t['process'] = subprocess.Popen(['bash', t['script']] + t['args'], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE)
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
            lines = f.readlines()[-50:]
        return jsonify({'logs': lines})
    except Exception as e:
        return jsonify({'logs': [f'Error reading logs: {str(e)}']})

@app.route('/api/tool/<tool>/metrics', methods=['GET'])
def metrics_tool(tool):
    if tool not in tool_scripts:
        return jsonify({'error': 'Unknown tool'}), 400
    
    # Return default metrics for now
    t = tool_scripts[tool]
    return jsonify({'metrics': t['metrics']})

@app.route('/api/system')
def system_stats():
    return jsonify({
        'cpu_percent': 0,
        'memory_percent': 0,
        'disk_usage': 0,
        'network_connections': 0
    })

if __name__ == '__main__':
    print("Starting CEG25 Blue Team Dashboard on http://localhost:5000")
    os.makedirs('/home/goodlife/Desktop/CEG25/blue-team-toolkit/logs', exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)