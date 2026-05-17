# Thiết kế hệ thống: WebSec Scanner

## 1. Kiến trúc tổng quan

```
Người dùng
    │
    │  python scanner.py --url https://example.com
    ▼
┌─────────────────────────────────────────────┐
│                  scanner.py                  │
│              (Entry Point / CLI)             │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│               ScanEngine                    │
│         (Điều phối các module)              │
└──┬───────┬───────┬───────┬───────┬──────────┘
   │       │       │       │       │
   ▼       ▼       ▼       ▼       ▼
Header  InfoDisc  HTTPS  PathScan  Cookie
Scanner Scanner  Checker  Scanner  Checker
                              │
                              ▼
                           CORS    Robots
                          Checker  Parser
                   │
                   ▼
┌─────────────────────────────────────────────┐
│             ReportGenerator                  │
│         (Xuất HTML + JSON)                  │
└─────────────────────────────────────────────┘
```

## 2. Cấu trúc thư mục

```
security-scanner/
│
├── scanner.py              ← Entry point (gọi source/engine.py)
│
├── source/                 ← Mã nguồn chính
│   ├── __init__.py
│   ├── config.py           ← Hằng số và cấu hình
│   ├── utils.py            ← Hàm tiện ích dùng chung
│   ├── engine.py           ← Điều phối modules, CLI, scoring
│   │
│   ├── modules/            ← Các module quét bảo mật
│   │   ├── __init__.py
│   │   ├── header_scanner.py   ← Module 1: HTTP Security Headers
│   │   ├── info_scanner.py     ← Module 2: Information Disclosure
│   │   ├── https_checker.py    ← Module 3: HTTPS/TLS + HTTP Redirect
│   │   ├── path_scanner.py     ← Module 4: Sensitive Paths (concurrent)
│   │   ├── cookie_checker.py   ← Module 5: Cookie Flags
│   │   ├── cors_checker.py     ← Module 6: CORS Policy
│   │   └── robots_parser.py    ← Module 7: Robots.txt
│   │
│   └── report/             ← Xuất báo cáo
│       ├── __init__.py
│       └── generator.py    ← Tạo báo cáo HTML, JSON, terminal (colorama)
│
├── wordlists/
│   └── sensitive_paths.txt ← Danh sách đường dẫn cần thử
│
├── docs/                   ← Tài liệu dự án
│   ├── topic.md
│   ├── proposal.md
│   ├── design.md
│   ├── tech.md
│   ├── requirement.md
│   ├── problem.md
│   └── pseudo.md
│
├── requirements.txt
├── LICENSE
└── README.md
```

## 3. Thiết kế dữ liệu

### 3.1 ScanResult — Kết quả của mỗi kiểm tra

Mỗi lần kiểm tra trả về một dict có cấu trúc thống nhất, được tạo bởi hàm `make_result()` trong `source/utils.py`:

```python
{
    "module": "Headers",              # Module nào thực hiện
    "check": "X-Frame-Options",       # Tên kiểm tra
    "status": "FAIL",                 # PASS / FAIL / WARN / INFO
    "severity": "MEDIUM",             # CRITICAL / HIGH / MEDIUM / LOW / INFO
    "description": "Thiếu header X-Frame-Options — cho phép tấn công Clickjacking",
    "fix": "Thêm header: X-Frame-Options: DENY"   # Khuyến nghị cách sửa (tùy chọn)
}
```

### 3.2 ScanReport — Báo cáo tổng hợp

```python
{
    "target": "https://example.com",
    "scan_time": "2024-01-15T09:30:00",   # ISO format
    "duration_seconds": 8.5,
    "score": 40,
    "score_label": "KÉM 🟠",
    "summary": {
        "total": 25,
        "passed": 10,
        "failed": 12,
        "warned": 3
    },
    "results": [
        { ... },   # ScanResult objects
        { ... },
    ]
}
```

### 3.3 Severity Levels — Mức độ nguy hiểm

| Level | Màu | Ý nghĩa |
|-------|-----|---------|
| CRITICAL | Đỏ đậm | Cần xử lý ngay, nguy cơ cao |
| HIGH | Đỏ | Vấn đề nghiêm trọng |
| MEDIUM | Cam | Vấn đề cần chú ý |
| LOW | Vàng | Vấn đề nhỏ |
| INFO | Xanh | Thông tin tham khảo |

## 4. Luồng xử lý chính (Main Flow)

```
Bước 1: Nhận URL từ CLI
    └─► Validate URL (có đúng định dạng không?)
    └─► Chuẩn hóa URL (thêm https:// nếu thiếu)

Bước 2: Gửi request ban đầu
    └─► GET request đến URL
    └─► Lưu response headers, status code, body
    └─► Xử lý lỗi (timeout, connection refused, ...)

Bước 3: Chạy từng module song song
    └─► header_scanner.scan(response)
    └─► info_scanner.scan(response)
    └─► https_checker.scan(url)
    └─► path_scanner.scan(url)        ← cần gửi nhiều request
    └─► cookie_checker.scan(response)
    └─► cors_checker.scan(url)
    └─► robots_parser.scan(url)

Bước 4: Thu thập kết quả
    └─► Tổng hợp tất cả ScanResult
    └─► Tính điểm tổng (security score)
    └─► Sắp xếp theo severity

Bước 5: Xuất báo cáo
    └─► Tạo file HTML từ template
    └─► Tạo file JSON
    └─► In tóm tắt ra terminal
```

## 5. Cách tính Security Score

Điểm bắt đầu từ 100, trừ điểm theo mức độ nghiêm trọng:

```
CRITICAL: -25 điểm mỗi vấn đề
HIGH:     -15 điểm mỗi vấn đề
MEDIUM:   -10 điểm mỗi vấn đề
LOW:       -5 điểm mỗi vấn đề
Tối thiểu: 0 điểm
```

Xếp loại:
```
80-100: 🟢 Tốt
60-79:  🟡 Trung bình — cần cải thiện
40-59:  🟠 Kém — có vấn đề đáng lo
0-39:   🔴 Nguy hiểm — cần xử lý ngay
```

## 6. Thiết kế giao diện báo cáo HTML

```
┌─────────────────────────────────────────────┐
│  WebSec Scanner Report                      │
│  Target: https://example.com                │
│  Scan time: 2024-01-15 09:30                │
├─────────────────────────────────────────────┤
│                                             │
│  Security Score: 45/100  🟠 KÉM            │
│                                             │
│  ✅ PASS: 10   ❌ FAIL: 12   ⚠️ WARN: 3    │
│                                             │
├─────────────────────────────────────────────┤
│  🔴 CRITICAL (1)                            │
│  ┌─────────────────────────────────────┐    │
│  │ .env file exposed                   │    │
│  │ File /.env tìm thấy và có thể đọc  │    │
│  │ Rủi ro: Lộ mật khẩu database       │    │
│  │ Cách sửa: Xóa hoặc chặn truy cập  │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  🟠 MEDIUM (5)                              │
│  ┌─────────────────────────────────────┐    │
│  │ ❌ X-Frame-Options missing          │    │
│  │ ❌ Content-Security-Policy missing  │    │
│  │ ❌ HSTS missing                     │    │
│  │ ...                                 │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  🟢 PASSED (10)                             │
│  ┌─────────────────────────────────────┐    │
│  │ ✅ HTTPS enabled                    │    │
│  │ ✅ Certificate valid (245 days)     │    │
│  │ ...                                 │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

## 7. Xử lý lỗi

| Tình huống | Xử lý |
|-----------|-------|
| URL không hợp lệ | Thông báo lỗi rõ ràng, dừng |
| Timeout kết nối | Thử lại 1 lần, sau đó ghi "Không thể kết nối" |
| SSL Error | Ghi nhận là vấn đề bảo mật, tiếp tục với HTTP |
| Status 404 | Vẫn scan headers, ghi nhận status |
| Redirect | Follow redirect tối đa 5 lần |
| Lỗi không mong đợi | Ghi log, bỏ qua module đó, tiếp tục |
