import socket

def scan_netbios_tcp(host, port):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "TCP/IP",
        "service": "netBIOS",
        "method": "banner grabbing",
        "banner": "",
        "error_message": "",
        "risk_vulnerabilities": ""
    }

    try:
        # TCP_139포트 열림 여부 확인
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((host, port))
        result["status"] = "open"
    except socket.error:
        result["error_message"] = "Port is closed"
        return result

    try:
        # netBIOS 139포트 배너그래빙
        req = b'\x81\x00\x00\x44'
        sock.sendall(req)
        banner = sock.recv(1024)
        sock.close()
        try:
            result["banner"] = banner.decode()
        except UnicodeDecodeError:
            result["banner"] = "Non-decodable data received"
        result["error_message"] = ""
        result["risk_vulnerabilities"] = " "

    except Exception as e:
        result["error_message"] = str(e)

    return result

