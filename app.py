from flask import Flask, request, jsonify, send_from_directory
import socket
import threading
import time
import os
from flask_cors import CORS
from waitress import serve

app = Flask(__name__, static_folder='.')
CORS(app)  # Enable CORS for all routes

scan_results = {}

@app.route('/scan', methods=['POST'])
def scan_ports():
    data = request.json
    host = data.get('host')
    port_range = data.get('port_range', '1-1024')
    timeout = data.get('timeout', 1)

    if not host:
        return jsonify({'error': 'Host is required'}), 400

    try:
        socket.gethostbyname(host)
        start_port, end_port = map(int, port_range.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            return jsonify({'error': 'Invalid port range'}), 400

        scan_key = f"{host}_{int(time.time())}"
        scan_thread = threading.Thread(target=run_scan, args=(host, start_port, end_port, float(timeout), scan_key))
        scan_thread.start()

        return jsonify({'message': 'Scan started', 'host': host, 'port_range': port_range, 'scan_key': scan_key})
    except socket.gaierror:
        return jsonify({'error': 'Invalid hostname or IP address'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid port range format. Use start-end (e.g., 1-1024)'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_scan(host, start_port, end_port, timeout, scan_key):
    results = []
    scan_results[scan_key] = {
        'host': host,
        'timestamp': int(time.time()),
        'status': 'scanning',
        'results': results
    }
    
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            connection = s.connect_ex((host, port))

            if connection == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"

                results.append({'port': port, 'status': 'open', 'service': service})
            s.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    
    # Update status to completed
    scan_results[scan_key]['status'] = 'completed'

    # Clean up old scan results
    keys = list(scan_results.keys())
    if len(keys) > 10:
        oldest_keys = sorted(keys, key=lambda k: scan_results[k]['timestamp'])[:len(keys)-10]
        for key in oldest_keys:
            del scan_results[key]

@app.route('/results', methods=['GET'])
def get_results():
    return jsonify(list(scan_results.values()))

@app.route('/results/<scan_key>', methods=['GET'])
def get_result_by_key(scan_key):
    if scan_key in scan_results:
        return jsonify(scan_results[scan_key])
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=10000)