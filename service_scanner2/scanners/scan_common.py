import socket

def scan(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            return {"port": port, "status": "open", "service": "", "banner": "", "error_message": ""}
        else:
            return {"port": port, "status": "closed", "service": "", "banner": "", "error_message": ""}
    except Exception as e:
        return {"port": port, "status": "error", "service": "", "banner": "", "error_message": str(e)}
    finally:
        sock.close()
