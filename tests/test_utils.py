"""
Test suite cho source/utils.py
Bao gồm: normalize_url, validate_url, is_soft_404, make_result,
load_wordlist_paths (với tmp file), get_score_label.
"""

import os
import pytest
from unittest.mock import MagicMock

from source.utils import (
    normalize_url, validate_url, is_soft_404,
    make_result, load_wordlist_paths, get_score_label
)


# ═══════════════════════════════════════════════
# normalize_url — thêm scheme nếu thiếu
# ═══════════════════════════════════════════════

class TestNormalizeUrl:
    """Kiểm tra hàm normalize_url xử lý scheme đúng cách."""

    def test_adds_https_when_no_scheme(self):
        """URL không có scheme → tự thêm https://"""
        assert normalize_url("example.com") == "https://example.com"

    def test_keeps_http_scheme(self):
        """URL đã có http:// → giữ nguyên, không đổi sang https"""
        assert normalize_url("http://example.com") == "http://example.com"

    def test_keeps_https_scheme(self):
        """URL đã có https:// → không thêm gì thêm"""
        assert normalize_url("https://example.com") == "https://example.com"

    def test_handles_url_with_path(self):
        """URL có path nhưng không có scheme → thêm https:// và giữ path"""
        result = normalize_url("example.com/admin/login")
        assert result == "https://example.com/admin/login"

    def test_handles_url_with_port(self):
        """URL có port → thêm scheme và giữ port"""
        result = normalize_url("localhost:8080")
        assert result == "https://localhost:8080"


# ═══════════════════════════════════════════════
# validate_url — kiểm tra URL hợp lệ
# ═══════════════════════════════════════════════

class TestValidateUrl:
    """Kiểm tra hàm validate_url phân biệt URL hợp lệ và không hợp lệ."""

    def test_valid_https_url(self):
        """URL HTTPS chuẩn → True"""
        assert validate_url("https://example.com") is True

    def test_valid_http_url(self):
        """URL HTTP chuẩn → True"""
        assert validate_url("http://example.com") is True

    def test_no_scheme_is_invalid(self):
        """URL thiếu scheme → False (urlparse không tách được)"""
        assert validate_url("example.com") is False

    def test_localhost_is_valid(self):
        """localhost không có dấu chấm nhưng vẫn hợp lệ"""
        assert validate_url("http://localhost") is True

    def test_localhost_with_port_is_valid(self):
        """localhost:8080 → hợp lệ"""
        assert validate_url("http://localhost:8080") is True

    def test_empty_string_is_invalid(self):
        """Chuỗi rỗng → False"""
        assert validate_url("") is False

    def test_only_scheme_is_invalid(self):
        """Chỉ có scheme mà không có domain → False"""
        assert validate_url("https://") is False

    def test_single_word_no_dot_is_invalid(self):
        """Một từ không có dấu chấm và không phải localhost → False"""
        assert validate_url("http://intranet") is False


# ═══════════════════════════════════════════════
# is_soft_404 — phát hiện trang 404 giả
# ═══════════════════════════════════════════════

class TestIsSoft404:
    """Kiểm tra hàm is_soft_404 phát hiện đúng trang 404 giả."""

    def _make_response(self, status_code=200, text=""):
        """Helper tạo mock response"""
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        return resp

    def test_detects_404_in_title(self):
        """Title chứa '404' → là soft 404"""
        resp = self._make_response(text="<html><title>404 Not Found</title><body>x</body></html>")
        assert is_soft_404(resp) is True

    def test_detects_page_not_found_in_title(self):
        """Title chứa 'page not found' → là soft 404"""
        resp = self._make_response(text="<html><title>Page Not Found</title><body>content</body></html>")
        assert is_soft_404(resp) is True

    def test_false_on_real_page(self):
        """Trang bình thường không chứa dấu hiệu 404 → False"""
        body = "<html><title>Welcome to my site</title><body>" + "a" * 2000 + "</body></html>"
        resp = self._make_response(text=body)
        assert is_soft_404(resp) is False

    def test_non_200_status_is_not_soft_404(self):
        """Status code != 200 thì không bao giờ là 'soft' 404"""
        resp = self._make_response(status_code=404, text="<title>404</title>")
        assert is_soft_404(resp) is False

    def test_short_body_with_not_found_keyword(self):
        """Body ngắn (< 1KB) chứa 'page not found' → là soft 404 (check body path)"""
        resp = self._make_response(text="<html><body>Sorry, page not found</body></html>")
        assert is_soft_404(resp) is True  # < 1KB + chứa "page not found" → match

    def test_long_body_without_title_not_soft_404(self):
        """Body dài (> 1KB) không có title 404 → không phải soft 404"""
        body = "<html><title>My Website</title><body>" + "content " * 300 + "</body></html>"
        resp = self._make_response(text=body)
        assert is_soft_404(resp) is False


# ═══════════════════════════════════════════════
# make_result — tạo dict kết quả chuẩn
# ═══════════════════════════════════════════════

class TestMakeResult:
    """Kiểm tra hàm make_result tạo đúng cấu trúc dict."""

    def test_has_all_required_keys(self):
        """Dict trả về phải có đủ các keys chuẩn mới"""
        result = make_result(
            module="Headers",
            check_name="CSP",
            status="FAIL",
            severity="HIGH",
            what_found="Thiếu CSP"
        )
        expected_keys = {
            "module", "check", "status", "severity", 
            "what_found", "description", "fix",
            "exposure_detail", "confidence", "confidence_reason", "manual_test"
        }
        assert expected_keys.issubset(result.keys())

    def test_values_match_input(self):
        """Giá trị trong dict phải khớp với tham số đầu vào"""
        result = make_result(
            module="HTTPS",
            check_name="TLS Version",
            status="PASS",
            severity="INFO",
            what_found="TLS 1.3 OK",
            confidence=100
        )
        assert result["module"] == "HTTPS"
        assert result["check"] == "TLS Version"
        assert result["status"] == "PASS"
        assert result["severity"] == "INFO"
        assert result["what_found"] == "TLS 1.3 OK"
        assert result["description"] == "TLS 1.3 OK"
        assert result["confidence"] == 100

    def test_fix_is_always_empty(self):
        """Trường fix phải luôn rỗng (theo triết lý mới)"""
        result = make_result("M", "C", "PASS", "INFO", "OK", fix="Nên sửa")
        assert result["fix"] == ""


# ═══════════════════════════════════════════════
# load_wordlist_paths — load file wordlist
# ═══════════════════════════════════════════════

class TestLoadWordlistPaths:
    """Kiểm tra load_wordlist_paths xử lý file đúng cách."""

    def test_loads_valid_file(self, tmp_path):
        """File hợp lệ → trả về list các path"""
        wl = tmp_path / "paths.txt"
        wl.write_text("/.env\n/.git/config\n/admin\n", encoding="utf-8")
        result = load_wordlist_paths(str(wl))
        assert result == ["/.env", "/.git/config", "/admin"]

    def test_skips_comments_and_blank_lines(self, tmp_path):
        """Dòng bắt đầu bằng # hoặc dòng trống bị bỏ qua"""
        wl = tmp_path / "paths.txt"
        wl.write_text("# Đây là comment\n\n/.env\n# comment khác\n/admin\n\n", encoding="utf-8")
        result = load_wordlist_paths(str(wl))
        assert result == ["/.env", "/admin"]

    def test_returns_none_for_missing_file(self):
        """File không tồn tại → trả về None"""
        result = load_wordlist_paths("/nonexistent/path/wordlist.txt")
        assert result is None

    def test_returns_none_for_corrupt_encoding(self, tmp_path):
        """File có encoding lỗi (binary) → trả về None thay vì crash"""
        wl = tmp_path / "corrupt.txt"
        wl.write_bytes(b"\x80\x81\x82\xff\xfe\xfd")
        result = load_wordlist_paths(str(wl))
        assert result is None

    def test_empty_file_returns_empty_list(self, tmp_path):
        """File rỗng → trả về list rỗng (không phải None)"""
        wl = tmp_path / "empty.txt"
        wl.write_text("", encoding="utf-8")
        result = load_wordlist_paths(str(wl))
        assert result == []


# ═══════════════════════════════════════════════
# get_score_label — nhãn đánh giá
# ═══════════════════════════════════════════════

class TestGetScoreLabel:
    """Kiểm tra get_score_label trả về nhãn đúng theo ngưỡng điểm audit."""

    def test_score_100_is_excellent(self):
        """Điểm 100 → EXCELLENT"""
        assert get_score_label(100) == "EXCELLENT"

    def test_score_95_is_excellent(self):
        """Điểm 95 → EXCELLENT"""
        assert get_score_label(95) == "EXCELLENT"

    def test_score_85_is_good(self):
        """Điểm 85 (>= 80) → GOOD"""
        assert get_score_label(85) == "GOOD"

    def test_score_65_is_fair(self):
        """Điểm 65 (>= 60) → FAIR"""
        assert get_score_label(65) == "FAIR"

    def test_score_45_is_poor(self):
        """Điểm 45 (>= 40) → POOR"""
        assert get_score_label(45) == "POOR"

    def test_score_20_is_critical(self):
        """Điểm 20 (< 40) → CRITICAL"""
        assert get_score_label(20) == "CRITICAL"
