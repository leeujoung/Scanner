from ftplib import FTP  # ftplib 모듈에서 FTP 클래스를 임포트

# FTP 포트를 스캔하는 함수
def scan(host, port):
    ftp = None  # FTP 객체 초기화
    try:
        ftp = FTP()
        ftp.connect(host, port, timeout=1)
        ftp.login()
        return {
            "port": port,
            "status": "open",
            "service": "ftp",
            "banner": ftp.getwelcome(),# FTP 서버의 환영 메시지(배너) 반환
            "error_message": ""
        }
    except Exception as e:
        return {
            "port": port,
            "status": "error",
            "error_message": str(e)  # 에러 발생 시 에러 메시지 반환
        }
    finally:
        if ftp is not None:  # FTP 객체가 생성되어 있다면
            try:
                ftp.quit()  # FTP 세션 종료
            except Exception:
                pass  # 종료 중 에러가 발생하더라도 무시


