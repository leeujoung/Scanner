import socket

def scan_service(host, port, service, protocol="TCP/IP"):
    result = {
        "port": port,
        "status": "closed",
        "protocol": protocol,
        "service": service,
        "method": "banner grabbing",
        "banner": "",
        "error_message": "",
        "risk_vulnerabilities": " "
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
        # Banner grabbing
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(1024).decode()
        result["banner"] = response.split('\r\n')[0]
    except Exception as e:
        result["error_message"] = str(e)
    finally:
        sock.close()

    return result

def scan_ssh(host, port=22):
    return scan_service(host, port, "SSH")

def scan_smtp(host, port=25):
    return scan_service(host, port, "SMTP")

def scan_dns(host, port=53):
    return scan_service(host, port, "DNS")

def scan_dhcp(host, port=67):
    return scan_service(host, port, "DHCP")

def scan_dhcp_client(host, port=68):
    return scan_service(host, port, "DHCP Client")

def scan_tftp(host, port=69):
    return scan_service(host, port, "TFTP")

def scan_gopher(host, port=70):
    return scan_service(host, port, "Gopher")

def scan_finger(host, port=79):
    return scan_service(host, port, "Finger")

def scan_kerberos(host, port=88):
    return scan_service(host, port, "Kerberos")

def scan_pop3(host, port=110):
    return scan_service(host, port, "POP3")

def scan_nntp(host, port=119):
    return scan_service(host, port, "NNTP")

def scan_ntp(host, port=123):
    return scan_service(host, port, "NTP")

def scan_netbios_tcp(host, port=135):
    return scan_service(host, port, "NetBIOS (TCP)")

def scan_netbios_udp(host, port=138):
    return scan_service(host, port, "NetBIOS (UDP)")

def scan_imap(host, port=143):
    return scan_service(host, port, "IMAP")

def scan_snmp(host, port=161):
    return scan_service(host, port, "SNMP")

def scan_bgp(host, port=179):
    return scan_service(host, port, "BGP")

def scan_irc(host, port=194):
    return scan_service(host, port, "IRC")

def scan_ldap(host, port=389):
    return scan_service(host, port, "LDAP")

def scan_smb(host, port=445):
    return scan_service(host, port, "SMB")

def scan_syslog(host, port=514):
    return scan_service(host, port, "Syslog")

def scan_rip(host, port=520):
    return scan_service(host, port, "RIP")

def scan_afp(host, port=548):
    return scan_service(host, port, "AFP")

def scan_ldaps(host, port=636):
    return scan_service(host, port, "LDAPS")

def scan_imaps(host, port=993):
    return scan_service(host, port, "IMAPS")

def scan_pop3s(host, port=995):
    return scan_service(host, port, "POP3S")

def scan_lotus_notes(host, port=1352):
    return scan_service(host, port, "Lotus Notes")

def scan_mssql(host, port=1433):
    return scan_service(host, port, "MSSQL")

def scan_oracle(host, port=1521):
    return scan_service(host, port, "Oracle")

def scan_h323(host, port=1720):
    return scan_service(host, port, "H323")

def scan_pptp(host, port=1723):
    return scan_service(host, port, "PPTP")

def scan_radius_auth(host, port=1812):
    return scan_service(host, port, "RADIUS Authentication")

def scan_radius_acct(host, port=1813):
    return scan_service(host, port, "RADIUS Accounting")

def scan_upnp(host, port=1900):
    return scan_service(host, port, "UPnP")

def scan_rdp(host, port=3389):
    return scan_service(host, port, "RDP")

def scan_postgresql(host, port=5432):
    return scan_service(host, port, "PostgreSQL")

def scan_http_alt(host, port=8080):
    return scan_service(host, port, "HTTP (Alternative)")

def scan_https_alt(host, port=8443):
    return scan_service(host, port, "HTTPS (Alternative)")

def scan_http_proxy(host, port=8888):
    return scan_service(host, port, "HTTP Proxy")
