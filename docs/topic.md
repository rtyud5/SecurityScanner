# Phân tích đề tài: Mini Security Scanner

## 1. Tổng quan đề tài

### Tên dự án
**WebSec Scanner** — Công cụ quét và đánh giá bảo mật website tự động

### Một câu mô tả
Một chương trình Python nhận vào URL của một website, tự động kiểm tra các vấn đề bảo mật phổ biến, và xuất ra báo cáo HTML trực quan — giúp người dùng biết website đó đang có lỗ hổng gì mà không cần công cụ thương mại đắt tiền.

### Vị trí trong ngành bảo mật
Dự án thuộc lĩnh vực **Web Application Security** và **Vulnerability Assessment** — một phần của quy trình Penetration Testing (kiểm thử xâm nhập) giai đoạn reconnaissance và scanning.

---

## 2. Bối cảnh và lý do chọn đề tài

### Thực trạng
- Hàng triệu website Việt Nam và thế giới đang chạy với cấu hình bảo mật mặc định — tức là không an toàn.
- Phần lớn quản trị viên website không có kiến thức chuyên sâu về bảo mật để tự kiểm tra.
- Các công cụ chuyên nghiệp như Nessus, Burp Suite Pro có giá hàng nghìn đô — không phù hợp với doanh nghiệp nhỏ hoặc cá nhân.
- Nhiều lỗ hổng cơ bản (missing headers, thông tin lộ ra, trang admin mặc định) hoàn toàn có thể phát hiện tự động bằng code đơn giản.

### Tại sao đề tài này phù hợp sinh viên năm 3 mới học ATTT
- Sử dụng Python — ngôn ngữ sinh viên CNTT đã biết
- Không cần phần cứng đặc biệt, không cần lab phức tạp
- Mỗi tính năng thêm vào tương ứng với 1 khái niệm bảo mật mới được học
- Có sản phẩm thực tế, chạy được, demo được
- Dễ mở rộng — có thể phát triển thêm sau khi nộp đồ án

### Tại sao có giá trị với nhà tuyển dụng / Bộ Công An
- Chứng minh hiểu biết thực tế về HTTP, web security, OWASP
- Có GitHub repository với code thật
- Có thể demo trực tiếp khi phỏng vấn
- Thể hiện tư duy defensive security — hiểu lỗ hổng để phòng chống

---

## 3. Phạm vi dự án

### Trong phạm vi (In Scope)
- Quét HTTP Security Headers
- Phát hiện thông tin server bị lộ
- Kiểm tra cấu hình HTTPS/TLS
- Phát hiện trang/đường dẫn nhạy cảm mặc định
- Kiểm tra Cookie flags
- Kiểm tra CORS policy
- Kiểm tra file nhạy cảm công khai (robots.txt, sitemap.xml, .env...)
- Xuất báo cáo HTML và JSON

### Ngoài phạm vi (Out of Scope)
- SQL Injection thực sự (cần xin phép, phức tạp hơn)
- XSS exploitation thực sự
- Brute force authentication
- Quét mạng nội bộ
- Bất kỳ hành động nào có thể gây hại cho hệ thống đích

> Lý do giới hạn: Tool này thuộc loại "passive/semi-passive scanning" — chỉ gửi các request HTTP bình thường, không khai thác lỗ hổng. Điều này giữ công cụ ở phạm vi hợp pháp và phù hợp với mục tiêu học tập.

---

## 4. Đối tượng sử dụng

| Đối tượng | Mục đích sử dụng |
|-----------|-----------------|
| Sinh viên ATTT | Học cách kiểm tra bảo mật website |
| Quản trị viên website nhỏ | Tự kiểm tra website của mình |
| Developer | Kiểm tra nhanh trước khi deploy |
| Người học bug bounty | Bước đầu recon mục tiêu |

---

## 5. Giá trị học thuật

### Kiến thức bảo mật được học qua từng module
| Module | Khái niệm bảo mật học được |
|--------|---------------------------|
| Header Scanner | HTTP Security Headers, OWASP Secure Headers Project |
| Info Disclosure | Information Leakage, Fingerprinting |
| HTTPS Checker | TLS/SSL, Certificate validation |
| Path Scanner | Directory Enumeration, Default Credentials risk |
| Cookie Checker | Cookie Security Flags, Session Hijacking |
| CORS Checker | Cross-Origin Resource Sharing, SOP |
| File Scanner | Sensitive File Exposure, Security Misconfiguration |

### Kỹ năng lập trình được rèn luyện
- Python: requests, argparse, concurrent.futures, json, jinja2
- Xử lý HTTP request/response
- Parsing HTML
- Viết report tự động
- Cấu trúc project Python chuyên nghiệp

---

## 6. So sánh với các tool tương tự

| Tool | Ưu điểm | Nhược điểm | Điểm khác biệt của dự án |
|------|---------|-----------|--------------------------|
| Nikto | Mạnh, nhiều check | Khó đọc output, không có GUI | Output HTML đẹp, dễ hiểu hơn |
| OWASP ZAP | Toàn diện | Nặng, khó dùng cho người mới | Nhẹ, chạy từ command line |
| SecurityHeaders.com | Dễ dùng | Online, không tùy chỉnh được | Offline, mã nguồn mở, mở rộng được |
| **Dự án này** | Đơn giản, có thể đọc hiểu toàn bộ code | Ít tính năng hơn tool chuyên nghiệp | Phù hợp học tập, tùy chỉnh dễ dàng |

---

## 7. Hướng mở rộng sau khi hoàn thành

Sau khi hoàn thành phiên bản cơ bản, có thể mở rộng:

**Mức trung bình:**
- Thêm kiểm tra SQL Injection cơ bản (trên lab của mình)
- Thêm kiểm tra XSS reflection cơ bản
- Thêm giao diện web (Flask) thay vì command line
- Tích hợp với VirusTotal API để kiểm tra domain

**Mức nâng cao:**
- Quét nhiều URL cùng lúc (multi-threading)
- Tích hợp CVE database
- Xuất báo cáo PDF
- Tạo dashboard theo dõi nhiều website
