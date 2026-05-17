"""
Module 1: Kiểm tra HTTP Security Headers
Kiểm tra sự tồn tại của các header bảo mật quan trọng trong HTTP response.
"""

from source.config import SECURITY_HEADERS
from source.utils import make_result


def check_headers(response):
    """
    Kiểm tra các HTTP Security Headers trong response.
    Mỗi header thiếu là một vấn đề bảo mật.

    Args:
        response: requests.Response object từ request ban đầu

    Returns:
        list[dict]: Danh sách ScanResult
    """
    results = []
    actual_headers = response.headers

    for h in SECURITY_HEADERS:
        if h["name"] in actual_headers:
            results.append(make_result(
                module="Headers",
                check_name=h["name"],
                status="PASS",
                severity="INFO",
                description=f"Header {h['name']} có mặt"
            ))
        else:
            results.append(make_result(
                module="Headers",
                check_name=h["name"],
                status="FAIL",
                severity=h["severity"],
                description=f"Thiếu header {h['name']} — {h['reason']}",
                fix=h["fix"]
            ))

    return results
