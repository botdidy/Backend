from flask import Flask, request, jsonify
import nmap
import ipaddress

app = Flask(_name_)

def calculate_subnet(ip_address):
    """Calculates the subnet based on the given IP address."""
    try:
        # Assuming a common /24 subnet (modify for other configurations)
        network = ipaddress.IPv4Network(f"{ip_address}/24", strict=False)
        return str(network)
    except Exception as e:
        raise ValueError(f"Invalid IP address: {e}")


@app.route('/scan', methods=['POST'])
def scan_network():
    data = request.json
    ip_address = data.get('ip_address')

    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400

    try:
        # Calculate subnet
        subnet = calculate_subnet(ip_address)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    scanner = nmap.PortScanner()
    devices = []

    try:
        # Perform network scan
        scanner.scan(hosts=subnet, arguments='-sn')  # '-sn' for ping sweep
        for host in scanner.all_hosts():
            devices.append({
                'ip': host,
                'status': scanner[host].state()
            })

        return jsonify({
            'subnet': subnet,
            'devices': devices
        }), 200

    except Exception as e:
        return jsonify({'error': f"Scan failed: {e}"}), 500


if _name_ == '_main_':
    app.run(debug=True)