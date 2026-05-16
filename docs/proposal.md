# Proposal: WebSec Scanner

## 1. Thông tin dự án

| Mục | Nội dung |
|-----|----------|
| Tên dự án | WebSec Scanner |
| Loại | Công cụ dòng lệnh (CLI Tool) |
| Ngôn ngữ | Python 3.10+ |
| Thời gian dự kiến | 8 tuần |
| Người thực hiện | Sinh viên năm 3 CNTT |
| Mục tiêu cuối | Đồ án môn An toàn thông tin |

---

## 2. Bối cảnh vấn đề

### Vấn đề thực tế
Một website bảo mật kém không có nghĩa là bị hack ngay lập tức — nhưng nó có nghĩa là khi hacker nhắm vào, họ sẽ thành công dễ dàng hơn. Hầu hết các lỗ hổng bảo mật cơ bản trên website không phải do code phức tạp gây ra, mà do **cấu hình sai** hoặc **bỏ quên** các thiết lập bảo mật đơn giản.

Ví dụ thực tế:
- Website thiếu header `X-Frame-Options` → hacker có thể nhúng website vào iframe để đánh lừa người dùng click (Clickjacking)
- Server trả về `Server: Apache/2.4.1` trong header → hacker biết chính xác phiên bản, tìm CVE phù hợp để khai thác
- Trang `/phpmyadmin` không bị chặn → hacker thử đăng nhập với mật khẩu mặc định

### Những ai bị ảnh hưởng
- Doanh nghiệp vừa và nhỏ tự quản lý website
- Developer không có nền tảng bảo mật
- Sinh viên học web development chưa biết về security

### Tại sao chưa có giải pháp tốt cho nhóm này
Các tool chuyên nghiệp (Nessus, Burp Suite) quá phức tạp và đắt. Các website kiểm tra online (securityheaders.com) thì tiện nhưng không tùy chỉnh được, không thể tích hợp vào quy trình làm việc.

---

## 3. Đề xuất giải pháp

Xây dựng một công cụ Python mã nguồn mở, chạy từ command line, thực hiện các kiểm tra bảo mật cơ bản trên một URL bất kỳ và xuất kết quả ra báo cáo HTML dễ đọc.

### Triết lý thiết kế

**Đơn giản:** Người dùng chỉ cần biết 1 lệnh để chạy.
```bash
python scanner.py --url https://example.com
```

**Rõ ràng:** Mỗi vấn đề tìm được đều có giải thích tại sao nguy hiểm và cách sửa.

**Trung thực:** Không khai thác, không gây hại — chỉ quan sát và báo cáo.

**Mở rộng được:** Cấu trúc module rõ ràng để thêm tính năng mới dễ dàng.

---

## 4. Mục tiêu cụ thể

### Mục tiêu kỹ thuật
- [ ] Quét và đánh giá ít nhất 7 loại vấn đề bảo mật
- [ ] Thời gian quét một URL dưới 30 giây
- [ ] Xuất báo cáo HTML đọc được trên mọi trình duyệt
- [ ] Xuất báo cáo JSON để tích hợp với tool khác
- [ ] Xử lý lỗi gracefully (timeout, URL không tồn tại, v.v.)

### Mục tiêu học tập
- [ ] Hiểu và giải thích được ít nhất 7 loại lỗ hổng web phổ biến
- [ ] Biết cách dùng thư viện `requests` nâng cao
- [ ] Biết cách tổ chức project Python theo chuẩn
- [ ] Biết đọc và phân tích HTTP request/response

---

## 5. Phạm vi và giới hạn đạo đức

### Công cụ này CHỈ được dùng để
- Quét website do chính mình sở hữu
- Quét website được chủ sở hữu cho phép rõ ràng bằng văn bản
- Quét trong môi trường lab/thực hành

### Công cụ này KHÔNG được dùng để
- Quét website người khác mà không có phép
- Khai thác bất kỳ lỗ hổng nào tìm được
- Thu thập thông tin với mục đích tấn công

> **Lưu ý pháp lý:** Việc quét website mà không có sự cho phép có thể vi phạm Luật An ninh mạng Việt Nam (Luật số 24/2018/QH14) và các quy định tương đương ở các quốc gia khác.

---

## 6. Kế hoạch thực hiện

```
Tuần 1-2:  Module 1 — HTTP Security Headers
Tuần 3-4:  Module 2 — Information Disclosure + HTTPS Check
Tuần 5-6:  Module 3 — Path Enumeration + Cookie/CORS Check
Tuần 7:    Report Generator (HTML + JSON)
Tuần 8:    Hoàn thiện, viết README, đóng gói
```

---

## 7. Định nghĩa "hoàn thành" (Definition of Done)

Dự án được coi là hoàn thành khi:
1. Tool chạy được với lệnh duy nhất `python scanner.py --url <URL>`
2. Tất cả 7 module kiểm tra hoạt động đúng
3. Báo cáo HTML xuất ra đọc được và có thông tin giải thích rõ ràng
4. Code có comment giải thích từng phần
5. README hướng dẫn cài đặt và sử dụng đầy đủ
6. Có thể demo trực tiếp trước hội đồng trong 10 phút
