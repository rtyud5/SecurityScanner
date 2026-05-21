"""
Module 7: Phân tích Robots.txt
Đọc robots.txt và tìm các đường dẫn nhạy cảm bị liệt kê trong Disallow.
"""

from source.utils import make_result, safe_get, get_base_url


def check_robots(url, verify_ssl=True):
    """
    Đọc robots.txt và tìm các đường dẫn nhạy cảm bị liệt kê trong Disallow.
    """
    results = []
    sensitive_keywords = ["admin", "backup", "api", "internal", "secret", "private", "config", "db", "upload", "dev", "staging"]
    base = get_base_url(url)

    r = safe_get(base + "/robots.txt", verify_ssl=verify_ssl)
    if r is None or r.status_code != 200:
        results.append(make_result(
            module="Robots.txt",
            check_name="Robots.txt Presence",
            status="PASS",
            severity="INFO",
            what_found="Không tìm thấy file robots.txt công khai.",
            confidence=100
        ))
        return results

    results.append(make_result(
        module="Robots.txt",
        check_name="Robots.txt Presence",
        status="INFO",
        severity="INFO",
        what_found="Tìm thấy file robots.txt.",
        confidence=100,
        exposure_detail={
            "leaked_data": [],
            "extra_intel": f"Content-Length: {len(r.text)} bytes",
            "attack_surface": "robots.txt cung cấp sơ đồ cấu trúc website cho search engine và cả attacker."
        }
    ))

    disallowed_paths = []
    sensitive_found = []

    for line in r.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if not path or path == "/": continue
            disallowed_paths.append(path)
            
            for keyword in sensitive_keywords:
                if keyword in path.lower():
                    sensitive_found.append(path)
                    break

    if sensitive_found:
        results.append(make_result(
            module="Robots.txt",
            check_name="Sensitive paths in robots.txt",
            status="WARN",
            severity="LOW",
            what_found=f"Phát hiện {len(sensitive_found)} đường dẫn nhạy cảm được liệt kê trong Disallow.",
            confidence=90,
            confidence_reason="Thông tin được trích xuất trực tiếp từ file robots.txt của server",
            exposure_detail={
                "leaked_data": sensitive_found[:10],
                "extra_intel": f"Tổng số Disallow: {len(disallowed_paths)}",
                "attack_surface": "Attacker thường quét robots.txt để tìm các trang quản trị, trang test, hoặc các thư mục không muốn search engine index nhưng lại chứa thông tin nhạy cảm."
            },
            manual_test=[
                {"step": 1, "action": "Kiểm tra trực tiếp các đường dẫn", "command": f"curl -I {base}{{path_found}}", "expected": "HTTP 200 hoặc 403 xác nhận vị trí tồn tại"}
            ]
        ))

    return results
