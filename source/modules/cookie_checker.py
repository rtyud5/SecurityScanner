"""
Module 5: Kiểm tra Cookie Security Flags
Kiểm tra các flag bảo mật Secure, HttpOnly, SameSite trên cookies.
"""

from source.utils import make_result


def check_cookies(response):
    """
    Kiểm tra các flag bảo mật của cookie.
    Cookie không có flag đúng có thể bị đánh cắp hoặc lạm dụng.

    Args:
        response: requests.Response object

    Returns:
        list[dict]: Danh sách ScanResult
    """
    results = []
    cookies = response.cookies

    if not cookies:
        results.append(make_result(
            module="Cookies",
            check_name="Cookies Present",
            status="INFO",
            severity="INFO",
            description="Không có cookie trong response này"
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
                description=f"Cookie '{name}' thiếu flag Secure — có thể bị gửi qua HTTP",
                fix=f"Thêm flag Secure vào cookie '{name}'"
            ))
        else:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': Secure flag",
                status="PASS",
                severity="INFO",
                description=f"Cookie '{name}' có flag Secure"
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
                description=f"Cookie '{name}' thiếu flag HttpOnly — JavaScript có thể đọc được",
                fix=f"Thêm flag HttpOnly vào cookie '{name}' để chống XSS đánh cắp session"
            ))
        else:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': HttpOnly flag",
                status="PASS",
                severity="INFO",
                description=f"Cookie '{name}' có flag HttpOnly"
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
                description=f"Cookie '{name}' thiếu flag SameSite — dễ bị tấn công CSRF",
                fix=f"Thêm flag SameSite=Lax hoặc SameSite=Strict vào cookie '{name}'"
            ))
        else:
            results.append(make_result(
                module="Cookies",
                check_name=f"Cookie '{name}': SameSite flag",
                status="PASS",
                severity="INFO",
                description=f"Cookie '{name}' có flag SameSite"
            ))

    return results
