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





# ═══════════════════════════════════════════════
# header_scanner — kiểm tra HTTP Security Headers
# ═══════════════════════════════════════════════

class TestHeaderScanner:
    """Kiểm tra check_headers phát hiện đúng header thiếu/có."""

    def test_missing_all_headers(self, make_mock_response):
        """Response không có header bảo mật nào → 6 kết quả FAIL"""
        response = make_mock_response(headers={})
        results = check_headers(response)

        fail_results = [r for r in results if r["status"] == "FAIL"]
        # config.py có 6 security headers
        assert len(fail_results) == 6

    def test_all_headers_present(self, make_mock_response):
        """Response có đầy đủ 6 header → 6 kết quả PASS"""
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }
        response = make_mock_response(headers=headers)
        results = check_headers(response)

        pass_results = [r for r in results if r["status"] == "PASS"]
        assert len(pass_results) == 6

    def test_has_csp_only(self, make_mock_response):
        """Chỉ có CSP → CSP là PASS, 5 cái còn lại FAIL"""
        headers = {"Content-Security-Policy": "default-src 'self'"}
        response = make_mock_response(headers=headers)
        results = check_headers(response)

        csp_result = next(r for r in results if r["check"] == "Content-Security-Policy")
        assert csp_result["status"] == "PASS"

        fail_results = [r for r in results if r["status"] == "FAIL"]
        assert len(fail_results) == 5

    def test_fail_results_have_attack_surface(self, make_mock_response):
        """Mỗi FAIL phải có thông tin attack surface"""
        response = make_mock_response(headers={})
        results = check_headers(response)

        for r in results:
            if r["status"] == "FAIL":
                assert r["exposure_detail"]["attack_surface"] != "", f"FAIL cho {r['check']} thiếu attack surface intel"

    def test_results_have_correct_module_name(self, make_mock_response):
        """Tất cả results phải có module = 'Headers'"""
        response = make_mock_response(headers={})
        results = check_headers(response)
        for r in results:
            assert r["module"] == "Headers"

    def test_partial_headers(self, make_mock_response):
        """Có 3/6 header → 3 PASS + 3 FAIL"""
        headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        response = make_mock_response(headers=headers)
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

    def test_no_cookies_returns_info(self, make_mock_response):
        """Response không có cookie → 1 kết quả INFO"""
        response = make_mock_response(cookies=[])
        results = check_cookies(response)

        assert len(results) == 1
        assert results[0]["status"] == "INFO"
        assert results[0]["module"] == "Cookies"

    def test_cookie_missing_secure_flag(self, make_mock_response, make_mock_cookie):
        """Cookie thiếu Secure → FAIL MEDIUM cho check Secure flag"""
        cookie = make_mock_cookie("session_id", secure=False, httponly=True, samesite=True)
        response = make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        secure_result = next(r for r in results if "Secure flag" in r["check"])
        assert secure_result["status"] == "FAIL"
        assert secure_result["severity"] == "MEDIUM"

    def test_cookie_missing_httponly_flag(self, make_mock_response, make_mock_cookie):
        """Cookie thiếu HttpOnly → FAIL MEDIUM"""
        cookie = make_mock_cookie("session_id", secure=True, httponly=False, samesite=True)
        response = make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        httponly_result = next(r for r in results if "HttpOnly flag" in r["check"])
        assert httponly_result["status"] == "FAIL"
        assert httponly_result["severity"] == "MEDIUM"

    def test_cookie_missing_samesite_flag(self, make_mock_response, make_mock_cookie):
        """Cookie thiếu SameSite → WARN LOW"""
        cookie = make_mock_cookie("csrf_token", secure=True, httponly=True, samesite=False)
        response = make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        samesite_result = next(r for r in results if "SameSite flag" in r["check"])
        assert samesite_result["status"] == "WARN"
        assert samesite_result["severity"] == "LOW"

    def test_cookie_all_flags_present(self, make_mock_response, make_mock_cookie):
        """Cookie có đủ 3 flag → 3 PASS"""
        cookie = make_mock_cookie("session_id", secure=True, httponly=True, samesite=True)
        response = make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        pass_results = [r for r in results if r["status"] == "PASS"]
        assert len(pass_results) == 3

    def test_cookie_all_flags_missing(self, make_mock_response, make_mock_cookie):
        """Cookie thiếu cả 3 flag → 2 FAIL + 1 WARN"""
        cookie = make_mock_cookie("token", secure=False, httponly=False, samesite=False)
        response = make_mock_response(cookies=[cookie])
        results = check_cookies(response)

        fail_results = [r for r in results if r["status"] == "FAIL"]
        warn_results = [r for r in results if r["status"] == "WARN"]
        assert len(fail_results) == 2   # Secure + HttpOnly
        assert len(warn_results) == 1   # SameSite

    def test_multiple_cookies(self, make_mock_response, make_mock_cookie):
        """Nhiều cookies → mỗi cookie được kiểm tra 3 flag riêng"""
        cookies = [
            make_mock_cookie("session", secure=True, httponly=True, samesite=True),
            make_mock_cookie("tracking", secure=False, httponly=False, samesite=False),
        ]
        response = make_mock_response(cookies=cookies)
        results = check_cookies(response)

        # Cookie 1: 3 PASS, Cookie 2: 2 FAIL + 1 WARN = tổng 6
        assert len(results) == 6
