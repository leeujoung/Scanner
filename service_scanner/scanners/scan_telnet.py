import socket

def scan_telnet(host, port):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "TCP/IP",
        "service": "Telnet",
        "method": "banner grabbing",
        "banner": "",
        "error_message": "",
        "risk_vulnerabilities": "Unencrypted communication, Potential for unauthorized access"
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        result["status"] = "open"

        try:
            # Telnet 배너를 읽기 위해 서버에 연결 후 데이터를 전송하고 수신
            sock.sendall(b"\r\n")  # Telnet 서버에 줄바꿈 문자를 전송하여 응답을 유도
            banner = b""
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                banner += data
            result["banner"] = banner.decode(errors='ignore')
            result["error_message"] = ""
            result["risk_vulnerabilities"] = " "
        except Exception as e:
            result["error_message"] = f"Failed to receive banner: {str(e)}"
        finally:
            sock.close()

    except socket.error as e:
        result["error_message"] = f"Port is closed or other socket error: {str(e)}"

    return result
