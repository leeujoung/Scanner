import socket
from ftplib import FTP

def scan_ftp(host, port=21):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "TCP/IP",
        "service": "FTP",
        "method": "banner grabbing",
        "banner": "",
        "error_message": "",
        "risk_vulnerabilities": "Anonymous access, Clear text transmission"
    }

    try:
        # 포트 열림 여부 확인
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        result["status"] = "open"
        sock.close()
    except socket.error:
        result["error_message"] = "Port is closed"
        return result

    try:
        # FTP 배너 그레이빙
        ftp = FTP()
        ftp.connect(host, port, timeout=2)
        welcome_message = ftp.getwelcome()
        ftp.quit()

        result["banner"] = welcome_message
        result["error_message"] = ""
        result["risk_vulnerabilities"] = " "

    except Exception as e:
        result["error_message"] = str(e)

    return result
