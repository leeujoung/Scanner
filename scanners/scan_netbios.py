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
        sock.settimeout(5)
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

def scan_netbios_udp(host, port):
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
        # UDP_137포트 열림 여부 확인
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(b'', (host, port))
        result["status"] = "open"

    except socket.error:
        result["error_message"] = "Port is closed"
        return result

    try:
        # netBIOS 137포트 배너그래빙
        req2 = b'\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
              b'\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41' + \
              b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
        sock.sendto(req2, (host, port))
        banner, addr = sock.recvfrom(1024)
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