import time
from portScannerApp.scanners.scan_functions import (
    scan_ftp, scan_http, scan_mysql
    # 필요한 경우 아래 주석을 해제하여 추가 포트를 가져옵니다.
    # scan_https, scan_ssh, scan_sql_server, scan_mongodb,scan_netbios,
    # scan_telnet, scan_smtp, scan_dns, scan_pop3,
    # scan_imap, scan_snmp, scan_kerberos, scan_smb,
    # scan_ldaps, scan_ftps, scan_imaps, scan_pop3s,
    # scan_rdp,  scan_bootp
)
# 포트와 서비스 이름 매핑
PORT_SERVICE_MAPPING = {
    80: scan_http,
    21: scan_ftp,
    3306: scan_mysql,
    22: scan_ssh,
    1433: scan_sql_server,
    443: scan_https,
    137: scan_netbios,
    138: scan_netbios,
    27017: scan_mongodb,
    23: scan_telnet,
    25: scan_smtp,
    53: scan_dns,
    110: scan_pop3,
    143: scan_imap,
    161: scan_snmp,
    162: scan_snmp,
    88: scan_kerberos,
    139: scan_smb,
    445: scan_smb,
    636: scan_ldaps,
    990: scan_ftps,
    993: scan_imaps,
    995: scan_pop3s,
    3389: scan_rdp,
    67: scan_bootp,
    68: scan_bootp
    # 필요한 추가 포트를 여기에 추가합니다.
}

def perform_scan(ip):
    start_time = time.time()

    results = []

    # 각 포트에 대해 스캔 수행
    for port, scan_function in PORT_SERVICE_MAPPING.items():
        result = scan_function(ip, port)
        results.append(result)

    end_time = time.time()
    duration = end_time - start_time

    return results, duration

def scanner_is_valid_ip(ip):
    # IP 유효성 검사를 수행하는 함수
    import re
    pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None