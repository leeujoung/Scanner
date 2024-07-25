import requests  # HTTP 요청을 보내기 위해 requests 라이브러리를 임포트

def scan(host, port):
    url = f"http://{host}:{port}" # 스캔할 URL을 생성
    try:
        response = requests.get(url, timeout=1) # HTTP GET 요청을 보내고 응답을 1초 안에 받기
         # 응답의 상태 코드와 헤더를 포함하여 결과 반환
        return {
            "port": port,
            "status": "open",
            "service": "http",
            "banner": response.headers.get('Server', ''),
            "error_message": ""
        }
    # 요청 중 예외가 발생하면 에러 메시지를 포함하여 결과 반환
    except Exception as e:
        return {"port": port, "status": "error", "service": "", "banner": "", "error_message": str(e)}
