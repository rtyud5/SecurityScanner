"""
Module 1: Kiểm tra HTTP Security Headers
Kiểm tra sự tồn tại của các header bảo mật quan trọng trong HTTP response.
"""

from source.config import SECURITY_HEADERS
from source.utils import make_result


def check_headers(response):
    """
    Kiểm tra các HTTP Security Headers trong response.
    """
    results = []
    actual_headers = response.headers
    base_url = response.url

    for h in SECURITY_HEADERS:
        header_name = h["name"]
        if header_name in actual_headers:
            value = actual_headers[header_name]
            if value.strip():
                results.append(make_result(
                    module="Headers",
                    check_name=header_name,
                    status="PASS",
                    severity="INFO",
                    what_found=f"Header {header_name} được phát hiện với giá trị: '{value}'",
                    confidence=100,
                    confidence_reason="Header tồn tại trực tiếp trong HTTP response"
                ))
            else:
                results.append(make_result(
                    module="Headers",
                    check_name=header_name,
                    status="FAIL",
                    severity=h["severity"],
                    what_found=f"Header {header_name} có mặt nhưng giá trị bị bỏ trống.",
                    confidence=70,
                    confidence_reason="Header tồn tại nhưng không có cấu hình (giá trị rỗng)",
                    exposure_detail={
                        "leaked_data": [],
                        "extra_intel": "Header present but empty.",
                        "attack_surface": h.get("attack", "")
                    }
                ))
        else:
            # Xử lý manual test template
            manual_test = []
            for step in h.get("manual_test", []):
                manual_test.append({
                    "step": step["step"],
                    "action": step["action"],
                    "command": step["command"].format(url=base_url),
                    "expected": step["expected"]
                })

            results.append(make_result(
                module="Headers",
                check_name=header_name,
                status="FAIL",
                severity=h["severity"],
                what_found=f"Thiếu header {header_name}. {h['reason']}",
                exposure_detail={
                    "leaked_data": [],
                    "extra_intel": f"Website không gửi header {header_name} trong response.",
                    "attack_surface": h.get("attack", "")
                },
                confidence=85,
                confidence_reason="Header hoàn toàn vắng mặt trong HTTP response headers",
                manual_test=manual_test
            ))

    return results
