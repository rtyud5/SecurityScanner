# Mã giả (Pseudocode) — Kiến trúc WebSec Scanner

Tài liệu này mô tả logic của từng thành phần bằng ngôn ngữ tự nhiên + code giả, trước khi viết code thật. Đọc file này giúp bạn hiểu "làm gì" trước khi lo "làm thế nào".

---

## 1. Entry Point — scanner.py

```
CHƯƠNG TRÌNH BẮT ĐẦU

1. Đọc tham số từ command line
   - Lấy --url (bắt buộc)
   - Lấy --output (tùy chọn, mặc định "report.html")
   - Lấy --json (tùy chọn, mặc định "report.json")

2. Validate URL
   - Nếu URL không có "http" ở đầu → thêm "https://"
   - Nếu URL vẫn không hợp lệ → in lỗi và thoát

3. In thông báo bắt đầu
   - "Đang quét: https://example.com"
   - "Thời gian bắt đầu: ..."

4. Gửi request ban đầu đến URL
   - Nếu thành công → lưu response để dùng chung
   - Nếu thất bại → in lỗi, một số module vẫn chạy được

5. Tạo ScanEngine và chạy tất cả module
   - Truyền URL và response vào engine
   - Engine chạy 7 module và thu thập kết quả

6. Tạo báo cáo
   - Tính Security Score
   - Xuất HTML
   - Xuất JSON

7. In tóm tắt ra terminal

CHƯƠNG TRÌNH KẾT THÚC
```

---

## 2. ScanEngine (source/engine.py)

```
HÀM run_scan(url, verify_ssl):
    results = []                    # Danh sách ScanResult

    GỬi request ban đầu đến url
    NẾU không kết nối được: in lỗi, trả về None

    Chạy từng module và gộp kết quả:
        [1/7] check_headers(response)
        [2/7] check_info_disclosure(response)
        [3/7] check_https(url)
        [4/7] check_sensitive_paths(url)     ← quét song song bên trong
        [5/7] check_cookies(response)
        [6/7] check_cors(url)
        [7/7] check_robots(url)

    Trả về results


HÀM calculate_score(results):
    score = 100
    
    VỚI mỗi result TRONG results:
        NẾU result.status == "FAIL":
            NẾU result.severity == "CRITICAL": score -= 25
            NẾU result.severity == "HIGH":     score -= 15
            NẾU result.severity == "MEDIUM":   score -= 10
            NẾU result.severity == "LOW":      score -= 5
    
    Trả về max(0, score)  ← Không xuống dưới 0


HÀM main():
    Đọc tham số CLI: --url, --output, --json, --no-verify, --verbose
    Normalize và validate URL
    Gọi run_scan() → results
    Tính score = calculate_score(results)
    Xuất báo cáo HTML + JSON + terminal
```

---

## 3. Module 1 — HeaderScanner

```
CLASS HeaderScanner:

    KHAI BÁO danh sách headers cần kiểm tra:
        HEADERS_TO_CHECK = [
            {
                tên: "Content-Security-Policy",
                mức độ: "HIGH",
                lý do thiếu: "Dễ bị XSS",
                cách sửa: "Thêm header CSP phù hợp"
            },
            {
                tên: "X-Frame-Options",
                mức độ: "MEDIUM",
                lý do thiếu: "Dễ bị Clickjacking",
                cách sửa: "Thêm: X-Frame-Options: DENY"
            },
            ... (6 headers tổng cộng)
        ]

    HÀM scan(url, response):
        results = []
        actual_headers = response.headers   ← Headers thực tế từ server
        
        VỚI mỗi header_info TRONG HEADERS_TO_CHECK:
            NẾU header_info.tên CÓ TRONG actual_headers:
                Tạo ScanResult(status=PASS, ...)
            NGƯỢC LẠI:
                Tạo ScanResult(status=FAIL, severity=header_info.mức_độ, ...)
            
            Thêm vào results
        
        Trả về results
```

---

## 4. Module 2 — InfoScanner

```
CLASS InfoScanner:

    HÀM scan(url, response):
        results = []
        
        --- Kiểm tra header Server ---
        server_header = response.headers.get("Server", không_có)
        
        NẾU server_header tồn tại:
            NẾU server_header chứa số phiên bản (vd: "Apache/2.4.1"):
                → FAIL: "Server header lộ phiên bản cụ thể"
                → severity: HIGH
            NGƯỢC LẠI:
                → WARN: "Server header tồn tại nhưng không lộ phiên bản"
                → severity: LOW
        NGƯỢC LẠI:
            → PASS: "Không có Server header"
        
        --- Kiểm tra header X-Powered-By ---
        powered_by = response.headers.get("X-Powered-By", không_có)
        
        NẾU powered_by tồn tại:
            → FAIL: "X-Powered-By lộ ngôn ngữ/framework: " + powered_by
            → severity: MEDIUM
        NGƯỢC LẠI:
            → PASS
        
        Trả về results
```

---

## 5. Module 3 — HttpsChecker (source/modules/https_checker.py)

```
HÀM check_https(url):
    results = []
    hostname = lấy_domain_từ_url(url)
    
    --- Kiểm tra HTTPS ---
    NẾU url bắt đầu bằng "http://":
        → FAIL: "Website không dùng HTTPS"
        → severity: HIGH
        Trả về results sớm (không cần kiểm tra certificate)
    
    --- Kiểm tra redirect HTTP → HTTPS ---
    http_url = "http://" + hostname
    response_http = gửi_request(http_url, follow_redirect=False)
    
    NẾU response_http.status_code là 301, 302, 307 hoặc 308:
        NẾU Location header chứa "https://":
            → PASS: "HTTP tự redirect sang HTTPS"
        NGƯỢC LẠI:
            → WARN: "HTTP redirect nhưng không sang HTTPS"
    NGƯỢC LẠI:
        → FAIL: "HTTP không redirect sang HTTPS"
    
    --- Kiểm tra TLS version ---
    CỐ GẮNG:
        kết nối SSL đến hostname:443
        tls_version = lấy_version_tls()
        
        NẾU tls_version là TLSv1 hoặc TLSv1.1:
            → FAIL: "TLS version đã deprecated"
            → severity: HIGH
        NGƯỢC LẠI:
            → PASS: ghi nhận version
    
    --- Kiểm tra certificate ---
    CỐ GẮNG:
        cert = lấy_ssl_certificate(hostname)
        ngày_hết_hạn = cert.not_after
        số_ngày_còn_lại = ngày_hết_hạn - hôm_nay (UTC)
        
        NẾU số_ngày_còn_lại < 0:
            → FAIL: "Certificate đã hết hạn"
            → severity: CRITICAL
        NGƯỢC LẠI NẾU số_ngày_còn_lại < 30:
            → WARN: "Certificate sắp hết hạn ({n} ngày)"
            → severity: MEDIUM
        NGƯỢC LẠI:
            → PASS: "Certificate còn hạn ({n} ngày)"
    
    XỬ LÝ LỖI SSL:
        → FAIL: "Không thể xác thực certificate"
    
    Trả về results
```

---

## 6. Module 4 — PathScanner

```
CLASS PathScanner:

    KHAI BÁO danh sách đường dẫn nhạy cảm:
        PATHS = đọc_từ_file("wordlists/sensitive_paths.txt")
        
        Hoặc hardcode:
        PATHS = [
            {"path": "/.env",         "severity": "CRITICAL", "mô_tả": "File chứa biến môi trường"},
            {"path": "/.git/config",  "severity": "CRITICAL", "mô_tả": "Git repository bị lộ"},
            {"path": "/phpmyadmin",   "severity": "HIGH",     "mô_tả": "Trang quản lý database"},
            {"path": "/admin",        "severity": "MEDIUM",   "mô_tả": "Trang quản trị"},
            {"path": "/robots.txt",   "severity": "INFO",     "mô_tả": "File robots"},
            ... (30+ paths)
        ]

    HÀM scan(url, response):
        results = []
        base_url = lấy_base_url(url)   ← "https://example.com"
        
        VỚI mỗi path_info TRONG PATHS:
            full_url = base_url + path_info.path
            
            CỐ GẮNG:
                r = gửi_request(full_url, timeout=5)
                
                NẾU r.status_code == 200:
                    → FAIL: "Tìm thấy: " + path_info.path
                    → severity: path_info.severity
                    → detail: "Nội dung có thể truy cập công khai"
                
                NGƯỢC LẠI NẾU r.status_code == 403:
                    → WARN: "Tồn tại nhưng bị chặn: " + path_info.path
                    → severity: LOW
                
                (Bỏ qua 404 và các status khác)
            
            XỬ LÝ LỖI timeout:
                Bỏ qua path này, tiếp tục
        
        Trả về results

    ← Ghi chú: Chạy song song với ThreadPoolExecutor để nhanh hơn
```

---

## 7. Module 5 — CookieChecker

```
CLASS CookieChecker:

    HÀM scan(url, response):
        results = []
        cookies = response.cookies
        
        NẾU không có cookie nào:
            → INFO: "Không có cookie trong response này"
            Trả về results
        
        VỚI mỗi cookie TRONG cookies:
            
            --- Kiểm tra Secure flag ---
            NẾU KHÔNG cookie.secure:
                → FAIL: "Cookie '{tên}' thiếu flag Secure"
                → severity: MEDIUM
                → detail: "Cookie có thể bị gửi qua HTTP không mã hóa"
            
            --- Kiểm tra HttpOnly flag ---
            NẾU KHÔNG cookie.httponly:
                → FAIL: "Cookie '{tên}' thiếu flag HttpOnly"
                → severity: MEDIUM
                → detail: "JavaScript có thể đọc cookie này — dễ bị XSS đánh cắp"
            
            --- Kiểm tra SameSite ---
            samesite = cookie.samesite
            NẾU samesite là None hoặc không tồn tại:
                → WARN: "Cookie '{tên}' thiếu thuộc tính SameSite"
                → severity: LOW
        
        Trả về results
```

---

## 8. Module 6 — CorsChecker

```
CLASS CorsChecker:

    HÀM scan(url, response):
        results = []
        
        --- Gửi request với Origin giả ---
        headers_giả = {"Origin": "https://evil-attacker.com"}
        r = gửi_request(url, headers=headers_giả)
        
        acao = r.headers.get("Access-Control-Allow-Origin", không_có)
        acac = r.headers.get("Access-Control-Allow-Credentials", "false")
        
        --- Phân tích ---
        NẾU acao == "*":
            NẾU acac == "true":
                → FAIL: "CORS: Allow-Origin=* kết hợp Allow-Credentials=true"
                → severity: HIGH
                → detail: "Cực kỳ nguy hiểm — mọi website đều có thể gửi request kèm cookie"
            NGƯỢC LẠI:
                → WARN: "CORS: Allow-Origin=* (chấp nhận được nếu API public)"
                → severity: LOW
        
        NGƯỢC LẠI NẾU acao == "https://evil-attacker.com":
            → FAIL: "CORS phản chiếu Origin của attacker"
            → severity: HIGH
        
        NGƯỢC LẠI NẾU acao không tồn tại:
            → PASS: "Không có CORS header"
        
        NGƯỢC LẠI:
            → INFO: "CORS được cấu hình: " + acao
        
        Trả về results
```

---

## 9. Module 7 — RobotsParser

```
CLASS RobotsParser:

    KHAI BÁO từ khóa nhạy cảm trong robots.txt:
        SENSITIVE_KEYWORDS = ["admin", "backup", "api", "internal", "secret", "private", "config"]

    HÀM scan(url, response):
        results = []
        robots_url = base_url(url) + "/robots.txt"
        
        r = gửi_request(robots_url)
        
        NẾU r.status_code != 200:
            → INFO: "Không có file robots.txt"
            Trả về results
        
        → INFO: "Tìm thấy robots.txt"
        
        --- Parse các Disallow entries ---
        disallowed_paths = []
        VỚI mỗi dòng TRONG r.text:
            NẾU dòng bắt đầu bằng "Disallow:":
                path = phần sau "Disallow:"
                thêm path vào disallowed_paths
        
        --- Kiểm tra xem có path nhạy cảm không ---
        VỚI mỗi path TRONG disallowed_paths:
            VỚI mỗi từ_khóa TRONG SENSITIVE_KEYWORDS:
                NẾU từ_khóa trong path:
                    → WARN: "robots.txt lộ đường dẫn nhạy cảm: " + path
                    → severity: LOW
        
        Trả về results
```

---

## 10. ReportGenerator

```
CLASS ReportGenerator:

    HÀM generate_html(scan_report, output_file):
        Đọc template HTML từ "report/template.html"
        
        Truyền vào template:
            - scan_report.target
            - scan_report.scan_time
            - scan_report.summary (score, counts)
            - scan_report.results (nhóm theo severity)
        
        Render template thành HTML string
        Ghi ra file output_file
        
        In: "Báo cáo HTML đã xuất: report.html"

    HÀM generate_json(scan_report, output_file):
        Chuyển scan_report thành dict Python
        Ghi ra file JSON với indent=2
        
        In: "Báo cáo JSON đã xuất: report.json"

    HÀM print_summary(scan_report):
        In ra terminal:
        
        "================================"
        "KẾT QUẢ QUÉT: https://example.com"
        "================================"
        "Security Score: 45/100 🟠 KÉM"
        ""
        "✅ PASS:  10"
        "❌ FAIL:  12"
        "⚠️  WARN:   3"
        ""
        "VẤN ĐỀ NGHIÊM TRỌNG:"
        "  🔴 [CRITICAL] .env file exposed"
        "  🟠 [HIGH]     Content-Security-Policy missing"
        "  ..."
        ""
        "Xem báo cáo đầy đủ: report.html"
```

---

## Tóm tắt luồng dữ liệu

```
URL (string)
    │
    ▼
requests.get(url)
    │
    ▼
response (object: headers, status_code, text, cookies)
    │
    ├──────────────────────────────────────┐
    │                                      │
    ▼                                      ▼
HeaderScanner.scan(response)         PathScanner.scan(url)
    │                                      │
    ▼                                      ▼
[ScanResult, ScanResult, ...]        [ScanResult, ScanResult, ...]
    │                                      │
    └──────────────┬───────────────────────┘
                   │
                   ▼
          all_results = [tất cả ScanResult từ 7 modules]
                   │
                   ▼
          ScanReport = {
              target, scan_time, summary, results
          }
                   │
            ┌──────┴──────┐
            ▼             ▼
        report.html   report.json
```
