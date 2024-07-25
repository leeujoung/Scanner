import socket

def scan_http(host, port=80):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "TCP/IP",
        "service": "HTTP",
        "method": "banner grabbing",
        "banner": "",
        "error_message": "",
        "risk_vulnerabilities": "Potential vulnerabilities such as outdated software"
    }

    try:
        # Check if the port is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        result["status"] = "open"
    except socket.error as e:
        result["error_message"] = str(e)
        return result

    try:
        # HTTP banner grabbing
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(1024).decode()
        result["banner"] = response.split('\r\n')[0]
    except Exception as e:
        result["error_message"] = str(e)
    finally:
        sock.close()

    return result
