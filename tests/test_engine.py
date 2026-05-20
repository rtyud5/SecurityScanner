"""
Test suite cho source/engine.py
Bao gồm: calculate_score — tính điểm bảo mật từ kết quả scan.
"""

import pytest

from source.engine import calculate_score
from source.utils import make_result


# ═══════════════════════════════════════════════
# calculate_score — tính Security Score
# ═══════════════════════════════════════════════

class TestCalculateScore:
    """Kiểm tra hàm calculate_score tính điểm chính xác."""

    def test_perfect_score_no_fails(self):
        """Không có FAIL nào → điểm 100"""
        results = [
            make_result("Headers", "CSP", "PASS", "INFO", "OK"),
            make_result("Headers", "XFO", "PASS", "INFO", "OK"),
            make_result("Cookies", "Secure", "PASS", "INFO", "OK"),
        ]
        assert calculate_score(results) == 100

    def test_one_critical_fail(self):
        """1 FAIL severity CRITICAL → trừ 25 điểm → 75"""
        results = [
            make_result("Path", ".env", "FAIL", "CRITICAL", "Lộ .env"),
            make_result("Headers", "CSP", "PASS", "INFO", "OK"),
        ]
        assert calculate_score(results) == 75

    def test_one_high_fail(self):
        """1 FAIL severity HIGH → trừ 15 điểm → 85"""
        results = [
            make_result("Headers", "CSP", "FAIL", "HIGH", "Thiếu CSP"),
        ]
        assert calculate_score(results) == 85

    def test_one_medium_fail(self):
        """1 FAIL severity MEDIUM → trừ 10 điểm → 90"""
        results = [
            make_result("Headers", "XFO", "FAIL", "MEDIUM", "Thiếu XFO"),
        ]
        assert calculate_score(results) == 90

    def test_one_low_fail(self):
        """1 FAIL severity LOW → trừ 5 điểm → 95"""
        results = [
            make_result("Headers", "Referrer", "FAIL", "LOW", "Thiếu Referrer"),
        ]
        assert calculate_score(results) == 95

    def test_info_fail_no_penalty(self):
        """FAIL severity INFO → trừ 0 điểm → vẫn 100"""
        results = [
            make_result("Path", "robots.txt", "FAIL", "INFO", "Tìm thấy robots.txt"),
        ]
        assert calculate_score(results) == 100

    def test_warn_not_counted(self):
        """WARN không bị trừ điểm — chỉ FAIL mới bị"""
        results = [
            make_result("HTTPS", "Redirect", "WARN", "MEDIUM", "Redirect lạ"),
            make_result("Path", "admin", "WARN", "LOW", "403 Forbidden"),
        ]
        assert calculate_score(results) == 100

    def test_multiple_fails_accumulate(self):
        """Nhiều FAIL tích lũy: CRITICAL(25) + HIGH(15) + MEDIUM(10) = trừ 50 → 50"""
        results = [
            make_result("Path", ".env", "FAIL", "CRITICAL", "Lộ .env"),
            make_result("Headers", "CSP", "FAIL", "HIGH", "Thiếu CSP"),
            make_result("Headers", "XFO", "FAIL", "MEDIUM", "Thiếu XFO"),
        ]
        assert calculate_score(results) == 50

    def test_floor_at_zero(self):
        """Nhiều FAIL → điểm không xuống dưới 0"""
        results = [
            make_result("A", "1", "FAIL", "CRITICAL", "x"),
            make_result("B", "2", "FAIL", "CRITICAL", "x"),
            make_result("C", "3", "FAIL", "CRITICAL", "x"),
            make_result("D", "4", "FAIL", "CRITICAL", "x"),
            make_result("E", "5", "FAIL", "CRITICAL", "x"),  # 5 × 25 = 125 > 100
        ]
        assert calculate_score(results) == 0

    def test_empty_results_perfect(self):
        """Danh sách rỗng → điểm 100 (không có gì sai)"""
        assert calculate_score([]) == 100

    def test_mixed_pass_fail_warn(self):
        """Hỗn hợp PASS + FAIL + WARN — chỉ FAIL bị trừ"""
        results = [
            make_result("H", "CSP", "PASS", "INFO", "OK"),
            make_result("H", "XFO", "FAIL", "MEDIUM", "Thiếu"),    # -10
            make_result("H", "HSTS", "WARN", "MEDIUM", "Cảnh báo"),  # không trừ
            make_result("P", ".env", "FAIL", "CRITICAL", "Lộ"),     # -25
        ]
        assert calculate_score(results) == 65
