# Yêu cầu dự án: WebSec Scanner

## 1. Yêu cầu chức năng (Functional Requirements)

### FR-01: Nhận URL đầu vào
- Tool nhận URL qua tham số `--url` từ command line
- Hỗ trợ cả `http://` và `https://`
- Tự động thêm `https://` nếu người dùng nhập thiếu scheme
- Hiển thị lỗi rõ ràng nếu URL không hợp lệ

### FR-02: Module Header Scanner
- Kiểm tra sự tồn tại của 6 security headers: `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`
- Trả về PASS nếu header có mặt, FAIL nếu thiếu

### FR-03: Module Information Disclosure
- Kiểm tra header `Server` có lộ phiên bản không
- Kiểm tra header `X-Powered-By` có tồn tại không
- Ghi nhận tên và phiên bản nếu tìm thấy

### FR-04: Module HTTPS Checker
- Kiểm tra website có dùng HTTPS không
- Kiểm tra HTTP có redirect sang HTTPS không
- Kiểm tra certificate còn hạn không
- Hiển thị số ngày còn lại của certificate

### FR-05: Module Path Scanner
- Thử ít nhất 30 đường dẫn nhạy cảm phổ biến
- Phân loại: tìm thấy (200), tồn tại nhưng bị chặn (403), không tồn tại (404)
- Đánh dấu mức độ nguy hiểm cho từng đường dẫn tìm thấy

### FR-06: Module Cookie Checker
- Kiểm tra tất cả cookie trong response
- Kiểm tra từng cookie có flag: `Secure`, `HttpOnly`, `SameSite`
- Báo cáo cookie nào thiếu flag nào

### FR-07: Module CORS Checker
- Gửi request với `Origin: https://evil.com`
- Kiểm tra response header `Access-Control-Allow-Origin`
- Phát hiện cấu hình CORS quá rộng (`*`)

### FR-08: Module Robots.txt Parser
- Tải và phân tích file `robots.txt`
- Liệt kê các đường dẫn trong `Disallow`
- Đánh dấu các đường dẫn nhạy cảm trong danh sách Disallow

### FR-09: Tính Security Score
- Tính điểm từ 0-100 dựa trên kết quả tất cả module
- Hiển thị điểm và xếp loại (Tốt / Trung bình / Kém / Nguy hiểm)

### FR-10: Xuất báo cáo HTML
- Tạo file HTML đọc được trên mọi trình duyệt
- Không cần internet để mở (CSS inline hoặc embedded)
- Hiển thị đầy đủ: score, tóm tắt, chi tiết từng vấn đề, khuyến nghị

### FR-11: Xuất báo cáo JSON
- Xuất toàn bộ kết quả dưới dạng JSON
- Có thể dùng để tích hợp với tool khác

### FR-12: Output terminal
- In tóm tắt kết quả ra terminal khi chạy xong
- Dùng màu để phân biệt PASS/FAIL/WARN

---

## 2. Yêu cầu phi chức năng (Non-Functional Requirements)

### NFR-01: Hiệu năng
- Thời gian quét tối đa 60 giây cho một URL
- Path scanning chạy song song, không tuần tự

### NFR-02: Xử lý lỗi
- Không crash khi gặp timeout, SSL error, connection refused
- Hiển thị thông báo lỗi thân thiện
- Tiếp tục các module khác khi 1 module lỗi

### NFR-03: Tính dễ đọc của code
- Mỗi module quét trong file riêng biệt dưới `source/modules/`
- Có docstring giải thích mỗi function
- Có comment tiếng Việt cho phần phức tạp

### NFR-04: Đạo đức
- Chỉ gửi các HTTP request thông thường
- Không thực hiện khai thác (exploitation)
- Có disclaimer rõ ràng về điều kiện sử dụng

---

## 3. Yêu cầu môi trường

| Yêu cầu | Tối thiểu |
|---------|----------|
| Python | 3.10+ |
| Hệ điều hành | Windows 10 / macOS / Ubuntu 20.04 |
| RAM | 512 MB |
| Kết nối mạng | Có — để kết nối tới target URL |

---

## 4. Tiêu chí chấp nhận (Acceptance Criteria)

Dự án được coi là đạt yêu cầu khi tất cả điều kiện sau đúng:

- [ ] Chạy được: `python scanner.py --url https://example.com` không báo lỗi
- [ ] 7 module đều hoạt động và trả về kết quả
- [ ] File `report.html` được tạo ra và mở được trên trình duyệt
- [ ] File `report.json` được tạo ra và parse được
- [ ] Xử lý được URL không tồn tại mà không crash
- [ ] Xử lý được URL chỉ có HTTP mà không crash
- [ ] Security Score hiển thị đúng
- [ ] README đủ để người khác cài và chạy được

---

## 5. Yêu cầu tài liệu

| Tài liệu | Nội dung |
|---------|---------|
| README.md | Giới thiệu, cài đặt, sử dụng, ví dụ output |
| docs/topic.md | Phân tích đề tài |
| docs/proposal.md | Đề xuất và bối cảnh |
| docs/design.md | Thiết kế hệ thống |
| docs/tech.md | Kỹ thuật sử dụng |
| docs/requirement.md | Tài liệu này |
| docs/problem.md | Chi tiết từng vấn đề bảo mật |
| docs/pseudo.md | Mã giả kiến trúc |
