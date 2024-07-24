import json
import csv
import os
from scanners.scan_functions import scan_ftp

def main():
    host = input("Enter the IP address of the server to scan: ")
    
    # 스캔할 포트와 그에 대응하는 스캔 함수 매핑
    ports = {
        21: scan_ftp,
    }
    
    results = []
    
    # 각 포트에 대해 스캔 수행
    for port, scan_function in ports.items():
        print(f"Scanning port {port}...")
        result = scan_function(host, port)
        results.append(result)
    
    # results 폴더가 존재하지 않으면 생성
    if not os.path.exists('results'):
        os.makedirs('results')
    
    # JSON 파일로 저장
    with open('results/scan_results.json', 'w') as json_file:
        json.dump(results, json_file, indent=4)
    
    # CSV 파일로 저장
    csv_columns = ["port", "status", "protocol", "service", "method", "banner", "error_message", "risk_vulnerabilities"]
    with open('results/scan_results.csv', 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
        writer.writeheader()
        for data in results:
            writer.writerow(data)

    print("Scan results have been saved to 'results/scan_results.json' and 'results/scan_results.csv'.")
    
    # Print scan results to the console
    print("\nScan Results:")
    for result in results:
        print(json.dumps(result, indent=4))
    
    
    print("완료되었습니다.")
    
    # 사용자 입력을 기다려 종료되지 않도록 함
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
