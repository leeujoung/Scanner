# scan_dns.py
import socket

def scan_dns(host, port=53):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "UDP",
        "service": "DNS",
        "banner": ""
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        query = b'\xaa\xaa'
        query += b'\x01\x00'
        query += b'\x00\x01'
        query += b'\x00\x00'
        query += b'\x00\x00'
        query += b'\x00\x00'
        query += b'\x00'
        query += b'\x00\x01'
        query += b'\x00\x01'

        sock.sendto(query, (host, port))

        response, _ = sock.recvfrom(512)
        result["status"] = "open"
        result["banner"] = response.hex()
    except socket.timeout:
        result["error_message"] = "Request timed out"
    except socket.error as e:
        result["error_message"] = str(e)
    finally:
        sock.close()

    return result
