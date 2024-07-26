from flask import Flask, render_template, request, jsonify, send_file
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask_socketio import SocketIO, emit
from fpdf import FPDF
import json
import os

# 포트 스캔 함수를 가져오는 부분을 확인하고 추가합니다.
from scanners.scan_functions import (
    scan_ftp, scan_http, scan_https, scan_mysql, scan_netbios_tcp, scan_netbios_udp, scan_telnet,
    scan_ssh, scan_smtp, scan_dns, scan_dhcp, scan_dhcp_client, scan_tftp, scan_gopher, scan_finger, scan_kerberos,
    scan_pop3, scan_nntp, scan_ntp, scan_imap, scan_snmp, scan_bgp, scan_irc, scan_ldap, scan_smb, scan_syslog, scan_rip,
    scan_afp, scan_ldaps, scan_imaps, scan_pop3s, scan_lotus_notes, scan_mssql, scan_oracle, scan_h323, scan_pptp,
    scan_radius_auth, scan_radius_acct, scan_upnp, scan_rdp, scan_postgresql, scan_http_alt, scan_https_alt, scan_http_proxy
)

app = Flask(__name__)
socketio = SocketIO(app)

# 스캔할 포트와 그에 대응하는 스캔 함수 매핑
ports = {
    21: scan_ftp,
    22: scan_ssh,
    25: scan_smtp,
    53: scan_dns,
    67: scan_dhcp,
    68: scan_dhcp_client,
    69: scan_tftp,
    70: scan_gopher,
    79: scan_finger,
    80: scan_http,
    88: scan_kerberos,
    110: scan_pop3,
    119: scan_nntp,
    123: scan_ntp,
    135: scan_netbios_tcp,
    138: scan_netbios_udp,
    143: scan_imap,
    161: scan_snmp,
    179: scan_bgp,
    194: scan_irc,
    389: scan_ldap,
    445: scan_smb,
    514: scan_syslog,
    520: scan_rip,
    548: scan_afp,
    636: scan_ldaps,
    993: scan_imaps,
    995: scan_pop3s,
    1352: scan_lotus_notes,
    1433: scan_mssql,
    1521: scan_oracle,
    1720: scan_h323,
    1723: scan_pptp,
    1812: scan_radius_auth,
    1813: scan_radius_acct,
    1900: scan_upnp,
    3389: scan_rdp,
    5432: scan_postgresql,
    8080: scan_http_alt,
    8443: scan_https_alt,
    8888: scan_http_proxy
}

def generate_pdf(results):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # 제목
        pdf.cell(200, 10, txt="Port Scan Results", ln=True, align='C')

        # 표 헤더
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(20, 10, txt="Port", border=1)
        pdf.cell(30, 10, txt="Status", border=1)
        pdf.cell(40, 10, txt="Service", border=1)
        pdf.cell(80, 10, txt="Banner", border=1)
        pdf.cell(20, 10, txt="Error", border=1)
        pdf.ln()

        # 표 내용
        pdf.set_font("Arial", size=12)
        for result in results:
            pdf.cell(20, 10, txt=str(result.get('port', '')), border=1)
            pdf.cell(30, 10, txt=result.get('status', ''), border=1)
            pdf.cell(40, 10, txt=result.get('service', ''), border=1)
            pdf.cell(80, 10, txt=result.get('banner', ''), border=1)
            pdf.cell(20, 10, txt=result.get('error_message', ''), border=1)
            pdf.ln()

        pdf_filename = "scan_results.pdf"
        pdf.output(pdf_filename)
        return pdf_filename
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None

def generate_json(results):
    try:
        json_filename = "scan_results.json"
        with open(json_filename, 'w') as json_file:
            json.dump(results, json_file, indent=4)
        return json_filename
    except Exception as e:
        print(f"Error generating JSON: {e}")
        return None

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@socketio.on('start_scan')
def handle_scan(data):
    ip = data['ip']
    socketio.emit('scan_update', {'target_ip': ip})  # Target IP 전송
    start_time = time.time()
    results = []
    
    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_function, ip, port): port for port, scan_function in ports.items()}

            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                socketio.emit('scan_update', result)

    except Exception as e:
        socketio.emit('scan_error', {'error': str(e)})
    
    end_time = time.time()
    duration = end_time - start_time
    socketio.emit('scan_complete', {'results': results, 'duration': duration})

@app.route('/download/<file_type>')
def download_file(file_type):
    results_str = request.args.get('results')
    results = json.loads(results_str)
    if file_type == 'pdf':
        pdf_filename = generate_pdf(results)
        return send_file(pdf_filename, as_attachment=True) if pdf_filename else "Error generating PDF"
    elif file_type == 'json':
        json_filename = generate_json(results)
        return send_file(json_filename, as_attachment=True) if json_filename else "Error generating JSON"
    else:
        return "Invalid file type requested"

if __name__ == '__main__':
    socketio.run(app, debug=True)
