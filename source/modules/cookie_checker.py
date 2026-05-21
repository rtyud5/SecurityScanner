"""
Module 5: Kiểm tra Cookie Security Flags
Kiểm tra các flag bảo mật Secure, HttpOnly, SameSite trên cookies.
"""

from source.utils import make_result


def check_cookies(response):
    """
    Kiểm tra các flag bảo mật của cookie.
    """
    results = []
    cookies = response.cookies

    if not cookies:
        results.append(make_result(
            module="Cookies",
            check_name="Cookies Present",
            status="INFO",
            severity="INFO",
            what_found="Không tìm thấy cookie nào được thiết lập trong response HTTP.",
            confidence=100
        ))
        return results

    for cookie in cookies:
        name = cookie.name

        # ── Kiểm tra Secure flag ──
        if not cookie.secure:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': Secure flag",
                status="FAIL",
                severity="MEDIUM",
                what_found=f"Cookie '{name}' thiếu thuộc tính 'Secure'.",
                confidence=95,
                exposure_detail={
                    "leaked_data": [f"Cookie name: {name}"],
                    "extra_intel": "",
                    "attack_surface": "Cookie có thể bị gửi qua kênh không mã hóa (HTTP), cho phép attacker chặn bắt session/dữ liệu bằng MitM."
                },
                manual_test=[
                    {"step": 1, "action": "Kiểm tra header Set-Cookie", "command": f"curl -I {response.url} | grep -i 'Set-Cookie'", "expected": f"Chuỗi '{name}' không đi kèm từ khóa 'Secure'"}
                ]
            ))
        else:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': Secure flag",
                status="PASS",
                severity="INFO",
                what_found=f"Cookie '{name}' có thuộc tính Secure."
            ))

        # ── Kiểm tra HttpOnly flag ──
        httponly = cookie.has_nonstandard_attr("httponly") or \
                   cookie.has_nonstandard_attr("HttpOnly")
        if not httponly:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': HttpOnly flag",
                status="FAIL",
                severity="MEDIUM",
                what_found=f"Cookie '{name}' thiếu thuộc tính 'HttpOnly'.",
                confidence=95,
                exposure_detail={
                    "leaked_data": [f"Cookie name: {name}"],
                    "extra_intel": "JavaScript document.cookie có thể đọc được cookie này.",
                    "attack_surface": "Nếu website bị lỗi XSS, attacker có thể sử dụng JavaScript để đánh cắp cookie này và chiếm đoạt phiên làm việc của người dùng."
                },
                manual_test=[
                    {"step": 1, "action": "Xác minh qua Browser Console", "command": "Mở F12 -> Console -> Nhập 'document.cookie'", "expected": f"Danh sách có chứa cookie '{name}'"}
                ]
            ))
        else:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': HttpOnly flag",
                status="PASS",
                severity="INFO",
                what_found=f"Cookie '{name}' có thuộc tính HttpOnly."
            ))

        # ── Kiểm tra SameSite flag ──
        samesite = cookie.has_nonstandard_attr("SameSite") or \
                   cookie.has_nonstandard_attr("samesite")
        if not samesite:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': SameSite flag",
                status="WARN",
                severity="LOW",
                what_found=f"Cookie '{name}' không định nghĩa thuộc tính 'SameSite'.",
                confidence=90,
                exposure_detail={
                    "leaked_data": [],
                    "extra_intel": "Trình duyệt mặc định có thể coi là SameSite=Lax nhưng không đảm bảo.",
                    "attack_surface": "Gia tăng rủi ro bị tấn công CSRF (Cross-Site Request Forgery) khi người dùng truy cập site độc hại."
                },
                manual_test=[
                    {"step": 1, "action": "Kiểm tra Application tab", "command": "F12 -> Application -> Cookies", "expected": f"Cột SameSite của '{name}' bị bỏ trống"}
                ]
            ))
        else:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': SameSite flag",
                status="PASS",
                severity="INFO",
                what_found=f"Cookie '{name}' có thuộc tính SameSite."
            ))

    return results
