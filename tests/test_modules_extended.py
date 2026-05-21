"""
Extended test cases cho source/modules/
Bao gồm: info_scanner và cors_checker.
Tập trung vào các edge cases và logic phức tạp.
"""
import pytest
from unittest.mock import patch, MagicMock
from source.modules.info_scanner import check_info_disclosure
from source.modules.cors_checker import check_cors

# ═══════════════════════════════════════════════
# TestInfoScanner
# ═══════════════════════════════════════════════

class TestInfoScanner:
    def test_server_header_with_version(self, make_mock_response):
        """Header Server chứa version → FAIL MEDIUM"""
        response = make_mock_response(headers={"Server": "Apache/2.4.1"})
        results = check_info_disclosure(response)
        server_result = next(r for r in results if r["check"] == "Server Header")
        assert server_result["status"] == "FAIL"
        assert server_result["severity"] == "MEDIUM"
        assert "Apache/2.4.1" in server_result["description"]

    def test_server_header_without_version(self, make_mock_response):
        """Header Server không chứa version → WARN LOW"""
        response = make_mock_response(headers={"Server": "nginx"})
        results = check_info_disclosure(response)
        server_result = next(r for r in results if r["check"] == "Server Header")
        assert server_result["status"] == "WARN"
        assert server_result["severity"] == "LOW"

    def test_no_server_header(self, make_mock_response):
        """Không có header Server → PASS INFO"""
        response = make_mock_response(headers={})
        results = check_info_disclosure(response)
        server_result = next(r for r in results if r["check"] == "Server Header")
        assert server_result["status"] == "PASS"
        assert server_result["severity"] == "INFO"

    def test_x_powered_by_present(self, make_mock_response):
        """Header X-Powered-By tồn tại → FAIL MEDIUM"""
        response = make_mock_response(headers={"X-Powered-By": "PHP/7.2.0"})
        results = check_info_disclosure(response)
        pb_result = next(r for r in results if r["check"] == "X-Powered-By Header")
        assert pb_result["status"] == "FAIL"
        assert pb_result["severity"] == "MEDIUM"

    def test_x_powered_by_absent(self, make_mock_response):
        """Không có X-Powered-By → PASS INFO"""
        response = make_mock_response(headers={})
        results = check_info_disclosure(response)
        pb_result = next(r for r in results if r["check"] == "X-Powered-By Header")
        assert pb_result["status"] == "PASS"
        assert pb_result["severity"] == "INFO"

    def test_aspnet_version_header(self, make_mock_response):
        """Header X-AspNet-Version tồn tại → FAIL MEDIUM"""
        response = make_mock_response(headers={"X-AspNet-Version": "4.0.30319"})
        results = check_info_disclosure(response)
        asp_result = next(r for r in results if r["check"] == "X-AspNet-Version Header")
        assert asp_result["status"] == "FAIL"
        assert asp_result["severity"] == "MEDIUM"

    def test_x_generator_header(self, make_mock_response):
        """Header X-Generator tồn tại → FAIL MEDIUM"""
        response = make_mock_response(headers={"X-Generator": "WordPress 6.0"})
        results = check_info_disclosure(response)
        gen_result = next(r for r in results if r["check"] == "X-Generator Header")
        assert gen_result["status"] == "FAIL"
        assert gen_result["severity"] == "MEDIUM"

    def test_version_regex_precision(self, make_mock_response):
        """Server với text không phải version x.x → WARN LOW"""
        # "ServerX" chứa chữ nhưng không có dạng d.d -> WARN
        response = make_mock_response(headers={"Server": "ServerX"})
        results = check_info_disclosure(response)
        server_result = next(r for r in results if r["check"] == "Server Header")
        assert server_result["status"] == "WARN"
        
        # "Version 1" cũng WARN vì regex tìm \d+\.\d+
        response = make_mock_response(headers={"Server": "Version 1"})
        results = check_info_disclosure(response)
        server_result = next(r for r in results if r["check"] == "Server Header")
        assert server_result["status"] == "WARN"

    def test_multiple_disclosure_headers(self, make_mock_response):
        """Có nhiều header lộ thông tin → nhiều FAIL"""
        headers = {
            "Server": "Apache/2.4.1",
            "X-Powered-By": "PHP/7.2",
            "X-AspNet-Version": "4.0"
        }
        response = make_mock_response(headers=headers)
        results = check_info_disclosure(response)
        fail_count = sum(1 for r in results if r["status"] == "FAIL")
        assert fail_count == 3

    def test_all_clean(self, make_mock_response):
        """Sạch sẽ hoàn toàn → toàn bộ PASS"""
        response = make_mock_response(headers={})
        results = check_info_disclosure(response)
        for r in results:
            assert r["status"] in ("PASS", "INFO")

# ═══════════════════════════════════════════════
# TestCorsChecker
# ═══════════════════════════════════════════════

class TestCorsChecker:
    @patch("source.modules.cors_checker.safe_get")
    def test_no_cors_header(self, mock_get, make_mock_response):
        """Server không trả về any CORS header → PASS"""
        mock_get.return_value = make_mock_response(headers={})
        results = check_cors("https://example.com")
        cors_result = next(r for r in results if r["check"] == "CORS Policy")
        assert cors_result["status"] == "PASS"
        assert "Không có CORS header" in cors_result["description"]

    @patch("source.modules.cors_checker.safe_get")
    def test_wildcard_origin(self, mock_get, make_mock_response):
        """ACAO: * (không credentials) → WARN LOW"""
        mock_get.return_value = make_mock_response(headers={"Access-Control-Allow-Origin": "*"})
        results = check_cors("https://example.com")
        cors_result = next(r for r in results if r["check"] == "CORS Policy")
        assert cors_result["status"] == "WARN"
        assert cors_result["severity"] == "LOW"

    @patch("source.modules.cors_checker.safe_get")
    def test_wildcard_with_credentials(self, mock_get, make_mock_response):
        """ACAO: * + ACAC: true → FAIL HIGH"""
        mock_get.return_value = make_mock_response(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        })
        results = check_cors("https://example.com")
        cors_result = next(r for r in results if r["check"] == "CORS Policy")
        assert cors_result["status"] == "FAIL"
        assert cors_result["severity"] == "HIGH"

    @patch("source.modules.cors_checker.safe_get")
    def test_reflected_origin(self, mock_get, make_mock_response):
        """ACAO phản chiếu Origin → FAIL HIGH"""
        fake_origin = "https://evil-attacker-site.com"
        mock_get.return_value = make_mock_response(headers={"Access-Control-Allow-Origin": fake_origin})
        results = check_cors("https://example.com")
        cors_result = next(r for r in results if r["check"] == "CORS Policy")
        assert cors_result["status"] == "FAIL"
        assert cors_result["severity"] == "HIGH"
        assert "phản chiếu Origin" in cors_result["description"]

    @patch("source.modules.cors_checker.safe_get")
    def test_safe_specific_origin(self, mock_get, make_mock_response):
        """ACAO: domain cụ thể (không phải evil) → PASS"""
        mock_get.return_value = make_mock_response(headers={"Access-Control-Allow-Origin": "https://trusted.com"})
        results = check_cors("https://example.com")
        cors_result = next(r for r in results if r["check"] == "CORS Policy")
        assert cors_result["status"] == "PASS"

    @patch("source.modules.cors_checker.safe_get")
    def test_null_origin_accepted(self, mock_get, make_mock_response):
        """Server chấp nhận null origin → FAIL HIGH"""
        # mock_get sẽ được gọi 2 lần: 1 cho fake origin, 1 cho null origin
        mock_get.side_effect = [
            make_mock_response(headers={}), # call 1: Origin: fake
            make_mock_response(headers={"Access-Control-Allow-Origin": "null"}) # call 2: Origin: null
        ]
        results = check_cors("https://example.com")
        null_result = next(r for r in results if r["check"] == "CORS Null Origin")
        assert null_result["status"] == "FAIL"
        assert null_result["severity"] == "HIGH"

    @patch("source.modules.cors_checker.safe_get")
    def test_null_origin_rejected(self, mock_get, make_mock_response):
        """Server không chấp nhận null origin → không có FAIL Null Origin"""
        mock_get.side_effect = [
            make_mock_response(headers={}), # call 1
            make_mock_response(headers={})  # call 2
        ]
        results = check_cors("https://example.com")
        null_results = [r for r in results if r["check"] == "CORS Null Origin"]
        assert len(null_results) == 0

    def test_result_module_name(self, make_mock_response):
        """Module name phải là CORS"""
        with patch("source.modules.cors_checker.safe_get") as mock_get:
            mock_get.return_value = make_mock_response(headers={})
            results = check_cors("https://example.com")
            for r in results:
                assert r["module"] == "CORS"

    @patch("source.modules.cors_checker.safe_get")
    def test_wildcard_credentials_severity_is_high(self, mock_get, make_mock_response):
        """Check severity HIGH cho * + credentials"""
        mock_get.return_value = make_mock_response(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        })
        results = check_cors("https://example.com")
        res = next(r for r in results if r["check"] == "CORS Policy")
        assert res["severity"] == "HIGH"

    @patch("source.modules.cors_checker.safe_get")
    def test_reflected_origin_fix_not_empty(self, mock_get, make_mock_response):
        """FAIL reflected origin phải có fix suggestion"""
        mock_get.return_value = make_mock_response(headers={"Access-Control-Allow-Origin": "https://evil-attacker-site.com"})
        results = check_cors("https://example.com")
        res = next(r for r in results if r["check"] == "CORS Policy")
        assert res["fix"] != ""

    @patch("source.modules.cors_checker.safe_get")
    def test_cors_policy_description_contains_origin(self, mock_get, make_mock_response):
        """Description của PASS nên chứa origin cụ thể"""
        mock_get.return_value = make_mock_response(headers={"Access-Control-Allow-Origin": "https://safe.com"})
        results = check_cors("https://example.com")
        res = next(r for r in results if r["check"] == "CORS Policy")
        assert "https://safe.com" in res["description"]

    @patch("source.modules.cors_checker.safe_get")
    def test_safe_get_returns_none(self, mock_get):
        """Nếu safe_get trả về None → trả về list rỗng"""
        mock_get.return_value = None
        results = check_cors("https://example.com")
        assert results == []
