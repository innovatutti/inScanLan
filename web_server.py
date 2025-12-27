"""
inScanLan - Versione Web/Mobile
Server Flask che funziona su qualsiasi dispositivo
"""

from flask import Flask, render_template, jsonify, request
import subprocess
import json
from network_scanner import NetworkScanner

app = Flask(__name__)
scanner = NetworkScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_network():
    data = request.json
    ip_range = data.get('ip_range', '192.168.1.0/24')
    ports = data.get('ports', [80, 443, 22])
    
    results = scanner.scan_network(ip_range, ports, {
        'ping': True,
        'port_scan': True,
        'arp': True,
        'netbios': False  # Non supportato su Android
    }, lambda msg, level: print(f"[{level}] {msg}"))
    
    return jsonify({'devices': results})

@app.route('/api/wifi/scan')
def wifi_scan():
    # Su Android usa termux-wifi-scaninfo
    try:
        result = subprocess.run(['termux-wifi-scaninfo'], 
                              capture_output=True, text=True)
        return jsonify({'networks': json.loads(result.stdout)})
    except:
        return jsonify({'error': 'WiFi scan non disponibile'}), 500

if __name__ == '__main__':
    # Accessibile da qualsiasi dispositivo sulla rete
    app.run(host='0.0.0.0', port=8080, debug=True)
