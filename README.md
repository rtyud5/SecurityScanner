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
```

## Kết quả

Sau khi chạy, tool tạo ra:
- `report.html` — Báo cáo trực quan, mở bằng trình duyệt
- `report.json` — Dữ liệu JSON thô

## Những gì được kiểm tra

| Module | Mô tả |
|--------|-------|
| HTTP Headers | Kiểm tra 6 security headers |
| Info Disclosure | Phát hiện thông tin server bị lộ |
| HTTPS/TLS | Kiểm tra certificate và cấu hình HTTPS |
| Path Scanner | Tìm đường dẫn nhạy cảm mặc định |
| Cookie Flags | Kiểm tra Secure, HttpOnly, SameSite |
| CORS | Phát hiện cấu hình CORS quá rộng |
| Robots.txt | Phân tích đường dẫn bị lộ trong robots.txt |

## Yêu cầu

- Python 3.10+
- Xem `requirements.txt`

## Tài liệu

Xem thư mục `docs/` để biết chi tiết thiết kế và kiến trúc dự án.
