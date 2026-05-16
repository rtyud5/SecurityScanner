# Các vấn đề bảo mật cần phát hiện

Mỗi vấn đề dưới đây là 1 module trong tool. Được sắp xếp từ dễ làm đến khó hơn.

---

## MODULE 1: HTTP Security Headers

### Vấn đề là gì?
HTTP Headers là phần thông tin phụ đi kèm mỗi response từ server. Có một số header đặc biệt liên quan đến bảo mật — nếu thiếu, trình duyệt không biết phải tự bảo vệ người dùng như thế nào.

### Các header cần kiểm tra

**X-Frame-Options**
- Thiếu header này → website có thể bị nhúng vào `<iframe>` của trang web độc hại
- Hacker dùng kỹ thuật "Clickjacking": người dùng nghĩ mình đang click vào trang lành, thực ra đang click vào website thật bên dưới
- Giá trị an toàn: `DENY` hoặc `SAMEORIGIN`

**X-Content-Type-Options**
- Thiếu → trình duyệt tự đoán loại file (MIME sniffing), có thể bị lợi dụng để chạy file độc hại
- Giá trị an toàn: `nosniff`

**Strict-Transport-Security (HSTS)**
- Thiếu → dù website có HTTPS, người dùng vẫn có thể bị ép kết nối HTTP không mã hóa
- Giá trị an toàn: `max-age=31536000; includeSubDomains`

**Content-Security-Policy (CSP)**
- Thiếu → website dễ bị tấn công XSS (Cross-Site Scripting)
- CSP cho phép website khai báo: "chỉ chạy script từ domain này, không chạy script lạ"
- Giá trị an toàn: tùy website, nhưng ít nhất phải có header này

**Referrer-Policy**
- Thiếu → khi người dùng click link ra ngoài, URL đầy đủ (kể cả token, ID) bị gửi kèm
- Giá trị an toàn: `strict-origin-when-cross-origin` hoặc `no-referrer`

**Permissions-Policy**
- Thiếu → website nhúng (iframe) có thể truy cập camera, microphone, location mà không hỏi
- Giá trị an toàn: `camera=(), microphone=(), geolocation=()`

### Cách kiểm tra
```python
response = requests.get(url)
headers = response.headers
# Kiểm tra từng header có trong headers hay không
```

### Mức độ nguy hiểm
| Header thiếu | Mức độ | Loại tấn công liên quan |
|---|---|---|
| Content-Security-Policy | CAO | XSS |
| X-Frame-Options | TRUNG BÌNH | Clickjacking |
| HSTS | TRUNG BÌNH | Man-in-the-Middle |
| X-Content-Type-Options | THẤP | MIME Sniffing |
| Referrer-Policy | THẤP | Information Leak |
| Permissions-Policy | THẤP | Feature Abuse |

---

## MODULE 2: Information Disclosure (Thông tin bị lộ)

### Vấn đề là gì?
Server vô tình tiết lộ thông tin về phần mềm đang chạy — phiên bản, ngôn ngữ, framework. Hacker dùng thông tin này để tìm CVE (lỗ hổng đã biết) phù hợp.

### Các thông tin cần kiểm tra

**Header "Server"**
- Xấu: `Server: Apache/2.4.1 (Ubuntu)` — lộ quá nhiều
- Tốt: `Server: nginx` hoặc không có header này
- Rất xấu: `Server: Microsoft-IIS/6.0` — phiên bản cũ, nhiều CVE đã biết

**Header "X-Powered-By"**
- Xấu: `X-Powered-By: PHP/7.2.0` — lộ ngôn ngữ và phiên bản
- Xấu: `X-Powered-By: ASP.NET`
- Tốt: không có header này

**Header "X-AspNet-Version"**
- Xấu: `X-AspNet-Version: 4.0.30319`

**Trang lỗi mặc định**
- Nhiều framework hiển thị trang lỗi với stack trace đầy đủ khi có exception
- Stack trace lộ: đường dẫn file trên server, tên biến, cấu trúc database

### Cách kiểm tra
```python
# Kiểm tra các header
server = response.headers.get("Server", "")
powered_by = response.headers.get("X-Powered-By", "")

# Kiểm tra trang lỗi: gửi request đến URL không tồn tại
error_response = requests.get(url + "/this-page-does-not-exist-12345")
# Phân tích body xem có stack trace không
```

---

## MODULE 3: HTTPS / TLS Configuration

### Vấn đề là gì?
HTTPS mã hóa dữ liệu giữa trình duyệt và server. Nhưng không phải cứ có HTTPS là an toàn — cấu hình sai vẫn có thể bị tấn công.

### Các điều cần kiểm tra

**Có HTTPS không?**
- Website chỉ có HTTP → toàn bộ dữ liệu truyền đi không mã hóa
- Bao gồm: mật khẩu, cookie, nội dung trang

**HTTP có tự redirect sang HTTPS không?**
- Nếu gõ `http://example.com` mà không redirect sang `https://` → người dùng dễ bị dùng HTTP mà không biết

**Certificate còn hạn không?**
- Certificate hết hạn → trình duyệt cảnh báo, người dùng mất tin tưởng
- Kiểm tra ngày hết hạn

**Certificate có match domain không?**
- Certificate cấp cho `example.com` nhưng đang dùng cho `sub.example.com` → cảnh báo

### Cách kiểm tra
```python
import ssl
import socket
from datetime import datetime

# Kiểm tra certificate
context = ssl.create_default_context()
conn = context.wrap_socket(socket.socket(), server_hostname=hostname)
conn.connect((hostname, 443))
cert = conn.getpeercert()

# Lấy ngày hết hạn
expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
days_left = (expire_date - datetime.now()).days
```

---

## MODULE 4: Sensitive Path Discovery (Đường dẫn nhạy cảm)

### Vấn đề là gì?
Nhiều website để lộ các trang quản trị, file cấu hình, hoặc trang debug mà không có bảo vệ. Hacker thường thử các đường dẫn phổ biến này đầu tiên.

### Danh sách đường dẫn cần thử

**Trang quản trị:**
```
/admin
/administrator
/wp-admin          (WordPress)
/wp-login.php      (WordPress)
/admin/login
/dashboard
/cpanel
/webmail
/phpmyadmin
/adminer.php
```

**File cấu hình và thông tin:**
```
/.env              (chứa database password, API key)
/config.php
/config.yml
/web.config
/.git/config       (lộ toàn bộ source code)
/.git/HEAD
/composer.json     (lộ dependencies)
/package.json
```

**File backup:**
```
/backup.zip
/backup.sql
/db.sql
/database.sql
/site.tar.gz
```

**Trang debug:**
```
/info.php          (phpinfo() — lộ toàn bộ cấu hình server)
/phpinfo.php
/test.php
/debug
```

**File thông tin:**
```
/robots.txt        (có thể lộ đường dẫn ẩn)
/sitemap.xml
/crossdomain.xml
/.htaccess
```

### Cách kiểm tra
```python
# Gửi GET request đến từng path
# Nếu status code 200 → tìm thấy
# Nếu 403 → tồn tại nhưng bị chặn (vẫn đáng ngờ)
# Nếu 404 → không tồn tại

for path in sensitive_paths:
    response = requests.get(url + path, timeout=5)
    if response.status_code == 200:
        # Tìm thấy! Kiểm tra thêm nội dung
    elif response.status_code == 403:
        # Tồn tại nhưng bị chặn
```

### Mức độ nguy hiểm
| Đường dẫn | Mức độ | Rủi ro |
|---|---|---|
| `/.env` | NGHIÊM TRỌNG | Lộ mật khẩu, API key |
| `/.git/config` | NGHIÊM TRỌNG | Lộ source code |
| `/phpmyadmin` | CAO | Truy cập database |
| `/info.php` | CAO | Lộ cấu hình server |
| `/wp-admin` | TRUNG BÌNH | Brute force admin |
| `/robots.txt` | THÔNG TIN | Lộ cấu trúc website |

---

## MODULE 5: Cookie Security Flags

### Vấn đề là gì?
Cookie lưu thông tin phiên đăng nhập. Nếu cookie bị đánh cắp, hacker đăng nhập được vào tài khoản người dùng mà không cần mật khẩu. Các "flag" của cookie giúp bảo vệ cookie khỏi bị đánh cắp.

### Các flag cần kiểm tra

**Secure flag**
- Thiếu → cookie được gửi qua cả HTTP (không mã hóa)
- Có flag → cookie chỉ được gửi qua HTTPS

**HttpOnly flag**
- Thiếu → JavaScript có thể đọc cookie → XSS đánh cắp cookie được
- Có flag → JavaScript không thể đọc cookie

**SameSite flag**
- Thiếu → cookie được gửi trong cross-site request → CSRF attack được
- Giá trị an toàn: `Strict` hoặc `Lax`

### Cách kiểm tra
```python
# Cookie nằm trong response headers
cookies = response.cookies
for cookie in cookies:
    secure = cookie.secure          # True/False
    httponly = cookie.has_nonstandard_attr('httponly')
    samesite = cookie.get_nonstandard_attr('samesite')
```

---

## MODULE 6: CORS Policy

### Vấn đề là gì?
CORS (Cross-Origin Resource Sharing) kiểm soát website nào được phép gọi API của bạn. Cấu hình sai có thể cho phép website độc hại đọc dữ liệu nhạy cảm từ API.

### Các trường hợp nguy hiểm

**`Access-Control-Allow-Origin: *`**
- Mọi website đều được phép gọi API → không sao nếu API public
- Nguy hiểm nếu API có dữ liệu nhạy cảm và dùng cookie authentication

**`Access-Control-Allow-Origin: null`**
- Cho phép request từ `null` origin — có thể bị lợi dụng

**`Access-Control-Allow-Credentials: true` kết hợp với `Allow-Origin: *`**
- Cực kỳ nguy hiểm — cho phép gửi cookie trong cross-origin request đến mọi domain

### Cách kiểm tra
```python
# Gửi request với Origin header giả
headers = {"Origin": "https://evil.com"}
response = requests.get(url, headers=headers)

acao = response.headers.get("Access-Control-Allow-Origin", "")
acac = response.headers.get("Access-Control-Allow-Credentials", "")
```

---

## MODULE 7: Robots.txt Analysis

### Vấn đề là gì?
File `robots.txt` hướng dẫn search engine không index một số trang. Nghịch lý: những gì trong `robots.txt` thường là những thứ chủ website muốn giấu — hacker đọc `robots.txt` để biết những trang "thú vị".

### Ví dụ robots.txt nguy hiểm
```
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /internal-api/
Disallow: /user-data/
```

→ Hacker biết có `/admin/`, `/backup/`, `/internal-api/` để thử.

### Cách kiểm tra
```python
response = requests.get(url + "/robots.txt")
if response.status_code == 200:
    # Parse các Disallow entries
    disallowed = []
    for line in response.text.split('\n'):
        if line.startswith('Disallow:'):
            path = line.split(':', 1)[1].strip()
            disallowed.append(path)
```

---

## Tóm tắt độ ưu tiên thực hiện

```
Ưu tiên 1 (Tuần 1-2): Module 1 — HTTP Headers        [Dễ nhất, học nhiều nhất]
Ưu tiên 2 (Tuần 3):   Module 2 — Info Disclosure      [Dễ, thực tế]
Ưu tiên 3 (Tuần 4):   Module 3 — HTTPS Check          [Cần học SSL cơ bản]
Ưu tiên 4 (Tuần 5):   Module 4 — Path Discovery       [Dễ code, nhiều ý nghĩa]
Ưu tiên 5 (Tuần 6):   Module 5 — Cookie Flags         [Cần hiểu cookie]
Ưu tiên 6 (Tuần 6):   Module 6 — CORS                 [Cần hiểu CORS]
Ưu tiên 7 (Tuần 7):   Module 7 — Robots.txt           [Dễ, làm cuối]
```
