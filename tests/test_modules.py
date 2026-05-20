"""
Test suite cho source/modules/
Bao gồm: header_scanner (check_headers), cookie_checker (check_cookies).
Dùng unittest.mock để mock HTTP response — không cần kết nối internet.
"""

import pytest
from unittest.mock import MagicMock
from http.cookiejar import Cookie

from source.modules.header_scanner import check_headers
from source.modules.cookie_checker import check_cookies


def _make_mock_response(headers=None, cookies=None, status_code=200, text=""):
    """
    Helper tạo mock response giống requests.Response.
    Dùng chung cho tất cả test trong file này.
    """
    response = MagicMock()
    response.headers = headers or {}
    response.status_code = status_code
    response.text = text

    # Mock cookies — cần giống interface của requests.cookies
    if cookies is None:
        response.cookies = []
    else:
        response.cookies = cookies

    return response


def _make_mock_cookie(name, secure=False, httponly=False, samesite=False):
    """
    Helper tạo mock cookie object với các flag cần thiết.
    Mock theo interface thực tế của http.cookiejar.Cookie mà requests dùng.
    """
    cookie = MagicMock()
    cookie.name = name
    cookie.secure = secure

    # has_nonstandard_attr() dùng để check HttpOnly và SameSite
    def _has_attr(attr_name):
        if attr_name.lower() == "httponly":
            return httponly
        if attr_name.lower() == "samesite":
            return samesite
        return False

    cookie.has_nonstandard_attr = MagicMock(side_effect=_has_attr)
    return cookie


# ═══════════════════════════════════════════════
# header_scanner — kiểm tra HTTP Security Headers
# ═══════════════════════════════════════════════

class TestHeaderScanner:
    """Kiểm tra check_headers phát hiện đúng header thiếu/có."""

    def test_missing_all_headers(self):
        """Response không có header bảo mật nào → 6 kết quả FAIL"""
        response = _make_mock_response(headers={})
        results = check_headers(response)

        fail_results = [r for r in results if r["status"] == "FAIL"]
        # config.py có 6 security headers
        assert len(fail_results) == 6

    def test_all_headers_present(self):
        """Response có đầy đủ 6 header → 6 kết quả PASS"""
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }
        response = _make_mock_response(headers=headers)
        results = check_headers(response)

        pass_results = [r for r in results if r["status"] == "PASS"]
        assert len(pass_results) == 6

    def test_has_csp_only(self):
        """Chỉ có CSP → CSP là PASS, 5 cái còn lại FAIL"""
        headers = {"Content-Security-Policy": "default-src 'self'"}
        response = _make_mock_response(headers=headers)
        results = check_headers(response)

        csp_result = next(r for r in results if r["check"] == "Content-Security-Policy")
        assert csp_result["status"] == "PASS"

        fail_results = [r for r in results if r["status"] == "FAIL"]
        assert len(fail_results) == 5

    def test_fail_results_have_fix_suggestion(self):
        """Mỗi FAIL phải có trường fix không rỗng (gợi ý cách sửa)"""
        response = _make_mock_response(headers={})
        results = check_headers(response)

        for r in results:
            if r["status"] == "FAIL":
                assert r["fix"] != "", f"FAIL cho {r['check']} thiếu fix suggestion"

    def test_results_have_correct_module_name(self):
        """Tất cả results phải có module = 'Headers'"""
        response = _make_mock_response(headers={})
        results = check_headers(response)
        for r in results:
            assert r["module"] == "Headers"

    def test_partial_headers(self):
        """Có 3/6 header → 3 PASS + 3 FAIL"""
        headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        response = _make_mock_response(headers=headers)
        results = check_headers(response)

        pass_count = sum(1 for r in results if r["status"] == "PASS")
        fail_count = sum(1 for r in results if r["status"] == "FAIL")
        assert pass_count == 3
        assert fail_count == 3


# ═══════════════════════════════════════════════
# cookie_checker — kiểm tra Cookie Security Flags
# ═══════════════════════════════════════════════

class TestCookieChecker:
    """Kiểm tra check_cookies phát hiện đúng flag thiếu trên cookies."""

    def test_no_cookies_returns_info(self):
        """Response không có cookie → 1 kết quả INFO"""
        response = _make_mock_response(cookies=[])
        results = check_cookies(response)

        assert len(results) == 1
        assert results[0]["status"] == "INFO"
        assert results[0]["module"] == "Cookies"

    def test_cookie_missing_secure_flag(self):
        """Cookie thiếu Secure → FAIL MEDIUM cho check Secure flag"""
        cookie = _make_mock_cookie("session_id", secure=False, httponly=True, samesite=True)
        response = _make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        secure_result = next(r for r in results if "Secure flag" in r["check"])
        assert secure_result["status"] == "FAIL"
        assert secure_result["severity"] == "MEDIUM"

    def test_cookie_missing_httponly_flag(self):
        """Cookie thiếu HttpOnly → FAIL MEDIUM"""
        cookie = _make_mock_cookie("session_id", secure=True, httponly=False, samesite=True)
        response = _make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        httponly_result = next(r for r in results if "HttpOnly flag" in r["check"])
        assert httponly_result["status"] == "FAIL"
        assert httponly_result["severity"] == "MEDIUM"

    def test_cookie_missing_samesite_flag(self):
        """Cookie thiếu SameSite → WARN LOW"""
        cookie = _make_mock_cookie("csrf_token", secure=True, httponly=True, samesite=False)
        response = _make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        samesite_result = next(r for r in results if "SameSite flag" in r["check"])
        assert samesite_result["status"] == "WARN"
        assert samesite_result["severity"] == "LOW"

    def test_cookie_all_flags_present(self):
        """Cookie có đủ 3 flag → 3 PASS"""
        cookie = _make_mock_cookie("session_id", secure=True, httponly=True, samesite=True)
        response = _make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        pass_results = [r for r in results if r["status"] == "PASS"]
        assert len(pass_results) == 3

    def test_cookie_all_flags_missing(self):
        """Cookie thiếu cả 3 flag → 2 FAIL + 1 WARN"""
        cookie = _make_mock_cookie("token", secure=False, httponly=False, samesite=False)
        response = _make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        fail_results = [r for r in results if r["status"] == "FAIL"]
        warn_results = [r for r in results if r["status"] == "WARN"]
        assert len(fail_results) == 2   # Secure + HttpOnly
        assert len(warn_results) == 1   # SameSite

    def test_multiple_cookies(self):
        """Nhiều cookies → mỗi cookie được kiểm tra 3 flag riêng"""
        cookies = [
            _make_mock_cookie("session", secure=True, httponly=True, samesite=True),
            _make_mock_cookie("tracking", secure=False, httponly=False, samesite=False),
        ]
        response = _make_mock_response(cookies=cookies)
        results = check_cookies(response)

        # Cookie 1: 3 PASS, Cookie 2: 2 FAIL + 1 WARN = tổng 6
        assert len(results) == 6
