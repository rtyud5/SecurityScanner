# Kỹ thuật: WebSec Scanner

## 1. Ngôn ngữ và phiên bản

| Thành phần | Lựa chọn | Lý do |
|-----------|----------|-------|
| Ngôn ngữ | Python 3.10+ | Sinh viên CNTT đã biết, thư viện phong phú |
| Package manager | pip | Mặc định, đơn giản |

---

## 2. Thư viện sử dụng

### requests
**Dùng để:** Gửi HTTP request, nhận response
```python
import requests
response = requests.get("https://example.com", timeout=10)
print(response.headers)   # HTTP headers
print(response.status_code)  # 200, 404, 500...
print(response.text)      # Nội dung trang
```
**Học gì từ đây:** HTTP request/response cycle, headers, status codes

---

### ssl (built-in)
**Dùng để:** Kiểm tra certificate HTTPS
```python
import ssl, socket
ctx = ssl.create_default_context()
conn = ctx.wrap_socket(socket.socket(), server_hostname="example.com")
conn.connect(("example.com", 443))
cert = conn.getpeercert()
```
**Học gì từ đây:** TLS/SSL handshake, certificate, HTTPS

---

### urllib.parse (built-in)
**Dùng để:** Parse và validate URL
```python
from urllib.parse import urlparse
parsed = urlparse("https://example.com/path")
print(parsed.scheme)    # "https"
print(parsed.netloc)    # "example.com"
print(parsed.path)      # "/path"
```

---

### argparse (built-in)
**Dùng để:** Xử lý tham số dòng lệnh
```python
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--url", required=True)
parser.add_argument("--output", default="report.html")
args = parser.parse_args()
```
**Kết quả:** `python scanner.py --url https://example.com --output my_report.html`

---

### concurrent.futures (built-in)
**Dùng để:** Chạy nhiều module song song (nhanh hơn)
```python
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(module.scan, url) for module in modules]
    results = [f.result() for f in futures]
```
**Học gì từ đây:** Multithreading, concurrent programming cơ bản

---

---

### json (built-in)
**Dùng để:** Xuất báo cáo JSON
```python
import json
with open("report.json", "w") as f:
    json.dump(scan_report, f, indent=2, ensure_ascii=False)
```

---

### colorama
**Dùng để:** In màu ra terminal (Windows compatible)
```python
from colorama import Fore, Style
print(Fore.RED + "FAIL" + Style.RESET_ALL)
print(Fore.GREEN + "PASS" + Style.RESET_ALL)
```

---

## 3. Tóm tắt requirements.txt

```
requests==2.31.0      # HTTP requests
colorama==0.4.6       # Màu terminal (PASS/FAIL/WARN)
urllib3==2.0.7        # Dependency của requests (SSL)
```

Phần còn lại (`ssl`, `socket`, `argparse`, `json`, `html`, `os`, `re`, `logging`, `concurrent.futures`, `urllib.parse`) là thư viện built-in của Python — không cần cài thêm.

> Ghi chú: Báo cáo HTML được tạo bằng f-string trong `source/report/generator.py`, không cần template engine bên ngoài.

---

## 4. Khái niệm HTTP cần hiểu

### HTTP Request
Khi bạn gõ URL vào trình duyệt, trình duyệt gửi:
```
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Accept: text/html
```

### HTTP Response
Server trả về:
```
HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx/1.18.0       ← Thông tin có thể khai thác
X-Frame-Options: DENY      ← Header bảo mật (tốt)
                           ← Nếu thiếu header bảo mật (xấu)

<!DOCTYPE html>
<html>...
```

### Status Codes quan trọng
| Code | Ý nghĩa |
|------|---------|
| 200 | OK — trang tồn tại |
| 301/302 | Redirect |
| 403 | Forbidden — tồn tại nhưng bị chặn |
| 404 | Not Found — không tồn tại |
| 500 | Server Error — lỗi server |

---

## 5. Lệnh cài đặt môi trường

```bash
# Tạo virtual environment (khuyến nghị)
python -m venv venv

# Kích hoạt (Windows)
venv\Scripts\activate

# Kích hoạt (Mac/Linux)
source venv/bin/activate

# Cài thư viện
pip install -r requirements.txt

# Chạy tool
python scanner.py --url https://example.com
```

---

## 6. Môi trường phát triển khuyến nghị

| Công cụ | Mục đích |
|---------|---------|
| VS Code | Editor chính, có extension Python tốt |
| Python extension for VS Code | Autocomplete, debug |
| Git + GitHub | Version control, lưu trữ code |
| Postman | Test HTTP request thủ công để học |
| Browser DevTools (F12) | Xem headers thực tế của website |

---

## 7. Cách học từng thư viện

**Tuần 1:** Học `requests`
- Đọc: https://docs.python-requests.org/en/latest/user/quickstart/
- Thực hành: Viết script gửi GET request đến 5 website, in ra headers

**Tuần 2:** Học `argparse`
- Đọc: https://docs.python.org/3/library/argparse.html
- Thực hành: Viết CLI tool nhỏ nhận tham số --url và --verbose

**Tuần 3-4:** Học `ssl` + HTTPS
- Đọc về TLS/SSL cơ bản trên Wikipedia
- Thực hành: Viết code kiểm tra certificate của google.com

**Tuần 5:** Học `jinja2`
- Đọc: https://jinja.palletsprojects.com/en/3.1.x/templates/
- Thực hành: Tạo template HTML đơn giản, render với dữ liệu Python
