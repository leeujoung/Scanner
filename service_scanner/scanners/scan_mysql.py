import socket

def parse_mysql_banner(banner):
    parts = banner.split('\x00')
    protocol_version = ord(parts[0][0])
    server_version = parts[1]
    connection_id = parts[2]
    return {
        "protocol_version": protocol_version,
        "server_version": server_version,
        "connection_id": connection_id,
        # 더 많은 데이터를 해석할 수 있음
    }

def scan_mysql(host, port):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "TCP/IP",
        "service": "MySQL",
        "method": "banner grabbing",
        "banner": "",
        "error_message": "",
        "risk_vulnerabilities": "Anonymous access, Clear text transmission"
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        result["status"] = "open"

        try:
            banner = sock.recv(1024).decode(errors='ignore')
            parsed_banner = parse_mysql_banner(banner)
            result["banner"] = parsed_banner
            result["error_message"] = ""
            result["risk_vulnerabilities"] = " "
        except Exception as e:
            result["error_message"] = f"Failed to receive banner: {str(e)}"
        finally:
            sock.close()

    except socket.error as e:
        result["error_message"] = f"Port is closed or other socket error: {str(e)}"

    return result
