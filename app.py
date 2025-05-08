from flask import Flask, request, jsonify, send_from_directory, make_response
import socket
import threading
import time
import os
from flask_cors import CORS
from waitress import serve
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.')
# Enable CORS with more specific configuration
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}}, supports_credentials=True)

scan_results = {}

@app.route('/scan', methods=['POST', 'OPTIONS'])
def scan_ports():
    if request.method == 'OPTIONS':
        # Handle OPTIONS request for CORS preflight
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response
        
    # Parse JSON with error handling
    try:
        data = request.json
    except Exception as e:
        logger.error(f"JSON parsing error: {e}")
        return jsonify({'error': 'Invalid JSON payload'}), 400
        
    host = data.get('host')
    port_range = data.get('port_range', '1-1024')
    timeout = data.get('timeout', 1)
    
    logger.info(f"Received scan request for host: {host}, port range: {port_range}")

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
        'results': results,
        'progress': 0,
        'total_ports': end_port - start_port + 1
    }
    
    total_ports = end_port - start_port + 1
    ports_checked = 0
    
    logger.info(f"Starting scan for {host} from port {start_port} to {end_port} with key {scan_key}")
    
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            connection = s.connect_ex((host, port))

            if connection == 0:
                try:
                    service = socket.getservbyport(port)
                except Exception:
                    service = "unknown"

                logger.info(f"Found open port {port} ({service}) on {host}")
                results.append({'port': port, 'status': 'open', 'service': service})
            s.close()
        except Exception as e:
            logger.error(f"Error scanning port {port}: {e}")
        
        # Update progress
        ports_checked += 1
        scan_results[scan_key]['progress'] = int((ports_checked / total_ports) * 100)
    
    # Update status to completed
    scan_results[scan_key]['status'] = 'completed'

    # Clean up old scan results
    keys = list(scan_results.keys())
    if len(keys) > 10:
        oldest_keys = sorted(keys, key=lambda k: scan_results[k]['timestamp'])[:len(keys)-10]
        for key in oldest_keys:
            del scan_results[key]

@app.route('/results', methods=['GET', 'OPTIONS'])
def get_results():
    if request.method == 'OPTIONS':
        # Handle OPTIONS request for CORS preflight
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET')
        return response
        
    response = make_response(jsonify(list(scan_results.values())))
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route('/results/<scan_key>', methods=['GET', 'OPTIONS'])
def get_result_by_key(scan_key):
    if request.method == 'OPTIONS':
        # Handle OPTIONS request for CORS preflight
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET')
        return response
        
    if scan_key in scan_results:
        response = make_response(jsonify(scan_results[scan_key]))
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint to verify the API is running"""
    return jsonify({"status": "ok"})

@app.errorhandler(Exception)
def handle_error(e):
    """Global error handler"""
    logger.error(f"Unhandled error: {str(e)}")
    return jsonify({"error": "Internal server error", "message": str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting port scanner application on port 10000")
    try:
        serve(app, host='0.0.0.0', port=10000)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")