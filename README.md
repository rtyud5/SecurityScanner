# WebSec Scanner

Công cụ Python quét bảo mật website cơ bản. Dành cho mục đích học tập.

> ⚠️ Chỉ dùng trên website bạn sở hữu hoặc được phép kiểm tra.

---

## Cài đặt

```bash
pip install -r requirements.txt
```

## Sử dụng

```bash
python scanner.py --url https://example.com
```

Tùy chọn:
```bash
python scanner.py --url https://example.com --output my_report.html --json my_report.json
python scanner.py --url https://example.com --no-verify --verbose
```

## Kết quả

Sau khi chạy, tool tạo ra:
- `report.html` — Báo cáo trực quan, mở bằng trình duyệt
- `report.json` — Dữ liệu JSON thô
- Terminal output — Tóm tắt có màu (PASS/FAIL/WARN)

## Những gì được kiểm tra

| Module | File | Mô tả |
|--------|------|-------|
| HTTP Headers | `source/modules/header_scanner.py` | Kiểm tra 6 security headers |
| Info Disclosure | `source/modules/info_scanner.py` | Phát hiện thông tin server bị lộ |
| HTTPS/TLS | `source/modules/https_checker.py` | HTTPS, HTTP→HTTPS redirect, certificate, TLS version |
| Path Scanner | `source/modules/path_scanner.py` | Tìm đường dẫn nhạy cảm (quét song song) |
| Cookie Flags | `source/modules/cookie_checker.py` | Kiểm tra Secure, HttpOnly, SameSite |
| CORS | `source/modules/cors_checker.py` | Phát hiện cấu hình CORS quá rộng |
| Robots.txt | `source/modules/robots_parser.py` | Phân tích đường dẫn bị lộ trong robots.txt |

## Cấu trúc dự án

```
security-scanner/
├── scanner.py              ← Entry point
├── source/                 ← Mã nguồn chính
│   ├── config.py           ← Hằng số và cấu hình
│   ├── utils.py            ← Hàm tiện ích dùng chung
│   ├── engine.py           ← Điều phối modules, CLI, scoring
│   ├── modules/            ← 7 modules quét bảo mật
│   └── report/             ← Xuất báo cáo HTML, JSON, terminal
├── wordlists/              ← Danh sách đường dẫn cần thử
├── docs/                   ← Tài liệu dự án
├── requirements.txt
└── README.md
```

## Yêu cầu

- Python 3.10+
- Xem `requirements.txt`

## Tài liệu

Xem thư mục `docs/` để biết chi tiết thiết kế và kiến trúc dự án.
