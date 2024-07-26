import socket

def scan_ftp(host, port=21):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "TCP/IP",
        "service": "FTP",
        "method": "banner grabbing",
        "banner": "",
        "error_message": "",
        "risk_vulnerabilities": ""
    }

    try:
        # 소켓 연결을 통해 포트가 열려 있는지 확인
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        result["status"] = "open"

        # FTP 서버로부터 환영 메시지 수신
        banner = sock.recv(1024).decode().strip()
        result["banner"] = banner

        sock.close()
    except socket.error as e:
        result["error_message"] = str(e)
    except Exception as e:
        result["error_message"] = str(e)
    finally:
        if sock:
            sock.close()

    return result
