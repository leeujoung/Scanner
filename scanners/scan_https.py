import ssl
import socket

def scan_https(host, port=443):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "TCP/IP",
        "service": "HTTPS",
        "method": "banner grabbing",
        "banner": "",
        "error_message": "",
        "risk_vulnerabilities": " "
    }

    try:
        # SSL/TLS 연결 설정
        context = ssl.create_default_context()
        sock = socket.create_connection((host, port), timeout=2)
        ssock = context.wrap_socket(sock, server_hostname=host)
        result["status"] = "open"
    except (socket.error, ssl.SSLError) as e:
        result["error_message"] = str(e)
        return result

    try:
        # 서버 인증서 가져오기
        cert = ssock.getpeercert()
        ssl_info = ssock.cipher()

        # 배너 정보 구성
        banner_info = {
            'subject': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'version': cert['version'],
            'serial_number': cert['serialNumber'],
            'not_before': cert['notBefore'],
            'not_after': cert['notAfter'],
            'cipher': ssl_info[0],
            'protocol': ssl_info[1],
            'key_exchange': ssl_info[2]
        }

        result["banner"] = banner_info
    except Exception as e:
        result["error_message"] = str(e)
    finally:
        ssock.close()

    return result

