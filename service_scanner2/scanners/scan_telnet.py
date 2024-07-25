import telnetlib

def scan(host, port):
    try:
        telnet = telnetlib.Telnet(host, port, timeout=1)
        banner = telnet.read_until(b"\n", timeout=1).decode('utf-8').strip()
        telnet.close()
        return {
            "port": port,
            "status": "open",
            "service": "telnet",
            "banner": banner,
            "error_message": ""
        }
    except Exception as e:
        return {
            "port": port,
            "status": "error",
            "service": "",
            "banner": "",
            "error_message": str(e)
        }
