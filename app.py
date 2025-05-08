from flask import Flask, request, jsonify, send_from_directory
import socket
import threading
import time
import os
from flask_cors import CORS



app = Flask(__name__, static_folder='.')
CORS(app)  # Enable CORS for all routes

@app.route('/scan', methods=['POST'])
def scan_ports():
    data = request.json
    host = data.get('host')
    port_range = data.get('port_range', '1-1024')
    timeout = data.get('timeout', 1)
    
    # Basic validation
    if not host:
        return jsonify({'error': 'Host is required'}), 400
    
    try:
        # Resolve the host to validate it
        socket.gethostbyname(host)
        
        # Parse port range
        start_port, end_port = map(int, port_range.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            return jsonify({'error': 'Invalid port range'}), 400
        
        # Start scan in a separate thread to avoid blocking
        scan_thread = threading.Thread(target=run_scan, args=(host, start_port, end_port, float(timeout)))
        scan_thread.start()
        
        return jsonify({'message': 'Scan started', 'host': host, 'port_range': port_range})
    
    except socket.gaierror:
        return jsonify({'error': 'Invalid hostname or IP address'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid port range format. Use start-end (e.g., 1-1024)'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

scan_results = {}

def run_scan(host, start_port, end_port, timeout):
    results = []
    
    for port in range(start_port, end_port + 1):
        try:
            # Create a new socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            
            # Attempt to connect
            connection = s.connect_ex((host, port))
            
            if connection == 0:
                # Try to get service name
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                results.append({
                    'port': port,
                    'status': 'open',
                    'service': service
                })
            
            # Close the socket
            s.close()
            
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    
    # Store results
    scan_key = f"{host}_{int(time.time())}"
    scan_results[scan_key] = {
        'host': host,
        'timestamp': int(time.time()),
        'results': results
    }
    
    # Clear old results (keep only the 10 most recent)
    keys = list(scan_results.keys())
    if len(keys) > 10:
        oldest_keys = sorted(keys, key=lambda k: scan_results[k]['timestamp'])[:len(keys)-10]
        for key in oldest_keys:
            del scan_results[key]

@app.route('/results', methods=['GET'])
def get_results():
    return jsonify(list(scan_results.values()))

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)