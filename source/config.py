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
        "fix": "Thêm header Content-Security-Policy với policy phù hợp"
    },
    {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "reason": "Thiếu header này cho phép tấn công Clickjacking",
        "fix": "Thêm: X-Frame-Options: DENY"
    },
    {
        "name": "Strict-Transport-Security",
        "severity": "MEDIUM",
        "reason": "Người dùng có thể bị ép dùng HTTP không mã hóa",
        "fix": "Thêm: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "LOW",
        "reason": "Trình duyệt có thể đoán sai loại file (MIME sniffing)",
        "fix": "Thêm: X-Content-Type-Options: nosniff"
    },
    {
        "name": "Referrer-Policy",
        "severity": "LOW",
        "reason": "URL đầy đủ (kể cả token) có thể bị lộ khi người dùng click link ngoài",
        "fix": "Thêm: Referrer-Policy: strict-origin-when-cross-origin"
    },
    {
        "name": "Permissions-Policy",
        "severity": "LOW",
        "reason": "Website nhúng có thể truy cập camera/mic mà không hỏi",
        "fix": "Thêm: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
]

# ─────────────────────────────────────────────
# DANH SÁCH ĐƯỜNG DẪN NHẠY CẢM (FALLBACK)
# ─────────────────────────────────────────────

SENSITIVE_PATHS = [
    {"path": "/.env",        "severity": "CRITICAL", "desc": "File chứa biến môi trường (mật khẩu, API key)"},
    {"path": "/.git/config", "severity": "CRITICAL", "desc": "Git repository bị lộ - có thể tải source code"},
    {"path": "/phpmyadmin",  "severity": "HIGH",     "desc": "Giao diện quản lý database phpMyAdmin"},
    {"path": "/adminer.php", "severity": "HIGH",     "desc": "Giao diện quản lý database Adminer"},
    {"path": "/info.php",    "severity": "HIGH",     "desc": "Trang phpinfo() lộ toàn bộ cấu hình server"},
    {"path": "/phpinfo.php", "severity": "HIGH",     "desc": "Trang phpinfo() lộ toàn bộ cấu hình server"},
    {"path": "/wp-admin",    "severity": "MEDIUM",   "desc": "Trang quản trị WordPress"},
    {"path": "/wp-login.php","severity": "MEDIUM",   "desc": "Trang đăng nhập WordPress"},
    {"path": "/admin",       "severity": "MEDIUM",   "desc": "Trang quản trị mặc định"},
    {"path": "/administrator","severity": "MEDIUM",  "desc": "Trang quản trị mặc định"},
    {"path": "/backup.sql",  "severity": "CRITICAL", "desc": "File backup database bị lộ"},
    {"path": "/db.sql",      "severity": "CRITICAL", "desc": "File database bị lộ"},
    {"path": "/robots.txt",  "severity": "INFO",     "desc": "File robots.txt (thông tin cấu trúc website)"},
    {"path": "/sitemap.xml", "severity": "INFO",     "desc": "File sitemap"},
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
