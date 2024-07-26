# scan_mongodb.py
import socket
import struct

def scan_mongodb(host, port=27017):
    result = {
        "port": port,
        "status": "closed",
        "protocol": "TCP/IP",
        "service": "MongoDB",
        "banner": ""
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        result["status"] = "open"
    except socket.error as e:
        result["error_message"] = str(e)
        return result

    try:
        isMaster = {
            "isMaster": 1,
            "client": {
                "driver": {
                    "name": "pymongo",
                    "version": "3.11.0"
                },
                "os": {
                    "type": "Linux"
                },
                "platform": "CPython 3.8.5"
            }
        }
        
        message = b'\x3a\x00\x00\x00'
        message += b'\x00\x00\x00\x00'
        message += b'\x00\x00\x00\x00'
        message += b'\xd4\x07\x00\x00'
        message += b'\x00'
        message += b'\x00\x00\x00\x00'
        message += b'\x03'
        message += b'\x00' * 8
        message += struct.pack("<I", 1)
        message += b'\x02\x10isMaster\x00' + struct.pack("<I", 1)
        
        sock.send(message)
        response = sock.recv(1024)
        result["banner"] = response.decode('latin1')
    except Exception as e:
        result["error_message"] = str(e)
    finally:
        sock.close()

    return result
