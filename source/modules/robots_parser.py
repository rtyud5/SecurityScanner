"""
Module 7: Phân tích Robots.txt
Đọc robots.txt và tìm các đường dẫn nhạy cảm bị liệt kê trong Disallow.
"""

from source.utils import make_result, safe_get, get_base_url


def check_robots(url, verify_ssl=True):
    """
    Đọc robots.txt và tìm các đường dẫn nhạy cảm bị liệt kê trong Disallow.
    Hacker thường đọc robots.txt để biết những trang "thú vị".

    Args:
        url: URL cần kiểm tra
        verify_ssl: Có kiểm tra SSL certificate không

    Returns:
        list[dict]: Danh sách ScanResult
    """
    results = []
    sensitive_keywords = ["admin", "backup", "api", "internal", "secret", "private", "config", "db"]
    base = get_base_url(url)

    r = safe_get(base + "/robots.txt", verify_ssl=verify_ssl)
    if r is None or r.status_code != 200:
        results.append(make_result(
            module="Robots.txt",
            check_name="Robots.txt",
            status="INFO",
            severity="INFO",
            description="Không tìm thấy file robots.txt"
        ))
        return results

    results.append(make_result(
        module="Robots.txt",
        check_name="Robots.txt",
        status="INFO",
        severity="INFO",
        description="Tìm thấy robots.txt"
    ))

    # Parse các Disallow entries
    for line in r.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if not path or path == "/":
                continue

            # Kiểm tra xem path có chứa từ khóa nhạy cảm không
            for keyword in sensitive_keywords:
                if keyword in path.lower():
                    results.append(make_result(
                        module="Robots.txt",
                        check_name="Sensitive path in robots.txt",
                        status="WARN",
                        severity="LOW",
                        description=f"robots.txt tiết lộ đường dẫn nhạy cảm: '{path}'",
                        fix="Kiểm tra lại xem đường dẫn này có cần bảo vệ thêm không"
                    ))
                    break

    return results
