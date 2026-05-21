"""
Cấu hình và hằng số cho WebSec Scanner.
Tất cả giá trị mặc định, danh sách kiểm tra, và scoring được định nghĩa tại đây.
"""

# ─────────────────────────────────────────────
# DANH SÁCH HTTP SECURITY HEADERS CẦN KIỂM TRA
# ─────────────────────────────────────────────

SECURITY_HEADERS = [
    {
        "name": "Content-Security-Policy",
        "severity": "HIGH",
        "reason": "Thiếu CSP làm website dễ bị tấn công XSS",
        "attack": "Attacker có thể thực thi JavaScript độc hại trên trình duyệt của người dùng để trộm session, redirect trang.",
        "manual_test": [
            {"step": 1, "action": "Kiểm tra header qua curl", "command": "curl -I {url}", "expected": "Header Content-Security-Policy không xuất hiện trong output"}
        ]
    },
    {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "reason": "Thiếu header này cho phép tấn công Clickjacking",
        "attack": "Attacker có thể nhúng website vào iframe trên trang độc hại để lừa người dùng click vào các nút ẩn.",
        "manual_test": [
            {"step": 1, "action": "Kiểm tra header qua curl", "command": "curl -I {url}", "expected": "Header X-Frame-Options không xuất hiện trong output"}
        ]
    },
    {
        "name": "Strict-Transport-Security",
        "severity": "MEDIUM",
        "reason": "Người dùng có thể bị ép dùng HTTP không mã hóa",
        "attack": "Attacker có thể thực hiện MitM (Man-in-the-Middle) để chặn và đọc dữ liệu truyền giữa client và server.",
        "manual_test": [
            {"step": 1, "action": "Kiểm tra header qua curl", "command": "curl -ls -I {url}", "expected": "Header Strict-Transport-Security không xuất hiện"}
        ]
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "LOW",
        "reason": "Trình duyệt có thể đoán sai loại file (MIME sniffing)",
        "attack": "Trình duyệt có thể thực thi một file text hoặc image như một script nếu attacker upload được file độc hại.",
        "manual_test": [
            {"step": 1, "action": "Kiểm tra header qua curl", "command": "curl -I {url}", "expected": "Header X-Content-Type-Options không xuất hiện hoặc thiếu giá trị 'nosniff'"}
        ]
    },
    {
        "name": "Referrer-Policy",
        "severity": "LOW",
        "reason": "URL đầy đủ (kể cả token) có thể bị lộ khi người dùng click link ngoài",
        "attack": "Thông tin nhạy cảm trong URL (vd: /reset-password?token=...) bị lộ qua header Referer khi người dùng chuyển trang.",
        "manual_test": [
            {"step": 1, "action": "Kiểm tra header qua curl", "command": "curl -I {url}", "expected": "Header Referrer-Policy không xuất hiện hoặc giá trị không an toàn"}
        ]
    },
    {
        "name": "Permissions-Policy",
        "severity": "LOW",
        "reason": "Website nhúng có thể truy cập camera/mic mà không hỏi",
        "attack": "Các bên thứ 3 (iframe/script) có thể lạm quyền sử dụng tài nguyên phần cứng của người dùng.",
        "manual_test": [
            {"step": 1, "action": "Kiểm tra header qua curl", "command": "curl -I {url}", "expected": "Header Permissions-Policy không xuất hiện"}
        ]
    },
]

# ─────────────────────────────────────────────
# DANH SÁCH ĐƯỜNG DẪN NHẠY CẢM (FALLBACK)
# ─────────────────────────────────────────────

SENSITIVE_PATHS = [
    {
        "path": "/.env",
        "severity": "CRITICAL",
        "desc": "File chứa biến môi trường (mật khẩu, API key)",
        "attack": "Attacker có được mật khẩu database, API keys để xâm nhập server hoặc dữ liệu người dùng.",
        "manual_test": [
            {"step": 1, "action": "Xác nhận file tồn tại", "command": "curl -s -I {url}/.env", "expected": "HTTP 200 OK"},
            {"step": 2, "action": "Kiểm tra nội dung", "command": "curl -s {url}/.env", "expected": "Danh sách biến dạng KEY=VALUE"}
        ]
    },
    {
        "path": "/.git/config",
        "severity": "CRITICAL",
        "desc": "Git repository bị lộ - có thể tải source code",
        "attack": "Attacker có thể clone toàn bộ source code, xem lịch sử commit và tìm thêm lỗ hổng bảo mật.",
        "manual_test": [
            {"step": 1, "action": "Xác nhận git config đọc được", "command": "curl -s {url}/.git/config", "expected": "Nội dung chứa section [core] hoặc [remote]"}
        ]
    },
    {
        "path": "/phpmyadmin",
        "severity": "HIGH",
        "desc": "Giao diện quản lý database phpMyAdmin",
        "attack": "Thực hiện brute-force mật khẩu hoặc dùng lỗ hổng để chiếm quyền điều khiển database.",
        "manual_test": [
            {"step": 1, "action": "Xác nhận trang tồn tại", "command": "curl -s -L {url}/phpmyadmin", "expected": "Trang đăng nhập phpMyAdmin"}
        ]
    },
    {
        "path": "/info.php",
        "severity": "HIGH",
        "desc": "Trang phpinfo() lộ toàn bộ cấu hình server",
        "attack": "Biết chính xác OS, PHP version, các thư viện cài đặt và đường dẫn tuyệt đối để leo thang tấn công.",
        "manual_test": [
            {"step": 1, "action": "Xác nhận trang tồn tại", "command": "curl -s {url}/info.php", "expected": "Trang phpinfo() chuẩn"}
        ]
    },
    {
        "path": "/backup.sql",
        "severity": "CRITICAL",
        "desc": "File backup database bị lộ",
        "attack": "Toàn bộ cấu trúc và dữ liệu database có thể bị tải xuống để trích xuất thông tin người dùng.",
        "manual_test": [
            {"step": 1, "action": "Xác nhận download", "command": "curl -I {url}/backup.sql", "expected": "HTTP 200 OK và Content-Type phù hợp (sql, octet-stream)"}
        ]
    },
    {
        "path": "/robots.txt",
        "severity": "INFO",
        "desc": "File robots.txt (thông tin cấu trúc website)",
        "attack": "Attacker tìm thấy danh sách các trang ẩn hoặc trang quản trị được khai báo trong Allow/Disallow.",
        "manual_test": [
            {"step": 1, "action": "Đọc file", "command": "curl -s {url}/robots.txt", "expected": "Nội dung User-agent và Disallow"}
        ]
    },
]

# ─────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────

SEVERITY_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 10, "LOW": 5, "INFO": 0}

# ─────────────────────────────────────────────
# HẰNG SỐ CẤU HÌNH
# ─────────────────────────────────────────────

CERT_EXPIRY_WARNING_DAYS = 30
DEFAULT_TIMEOUT = 10
DEFAULT_TLS_PORT = 443
MAX_PATH_WORKERS = 10
USER_AGENT = "WebSec-Scanner/1.0 (Security Audit Tool)"

# Dấu hiệu nhận biết trang 404 giả (soft 404)
SOFT_404_SIGNATURES = [
    "page not found", "404", "not found", "doesn't exist",
    "does not exist", "no longer available", "không tìm thấy",
    "trang không tồn tại"
]
