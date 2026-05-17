"""
Module 2: Kiểm tra Information Disclosure (Thông tin bị lộ)
Phát hiện các header lộ thông tin về server, framework, phiên bản phần mềm.
"""

import re
from source.utils import make_result


def check_info_disclosure(response):
    """
    Kiểm tra các thông tin server bị lộ trong headers.
    Hacker dùng thông tin này để tìm CVE phù hợp.

    Args:
        response: requests.Response object

    Returns:
        list[dict]: Danh sách ScanResult
    """
    results = []

    # ── Kiểm tra header "Server" ──
    server = response.headers.get("Server", "")
    if server:
        # Dùng regex để phát hiện pattern version (vd: Apache/2.4.1, nginx/1.18.0)
        version_pattern = re.compile(r"\d+\.\d+")
        has_version = bool(version_pattern.search(server))
        if has_version:
            results.append(make_result(
                module="Info Disclosure",
                check_name="Server Header",
                status="FAIL",
                severity="MEDIUM",
                description=f"Header Server lộ phiên bản: '{server}'",
                fix="Cấu hình server để ẩn phiên bản, hoặc xóa header Server"
            ))
        else:
            results.append(make_result(
                module="Info Disclosure",
                check_name="Server Header",
                status="WARN",
                severity="LOW",
                description=f"Header Server tồn tại: '{server}' (không lộ phiên bản)",
                fix="Nên xóa hoàn toàn header Server"
            ))
    else:
        results.append(make_result(
            module="Info Disclosure",
            check_name="Server Header",
            status="PASS",
            severity="INFO",
            description="Không có header Server — tốt"
        ))

    # ── Kiểm tra header "X-Powered-By" ──
    powered_by = response.headers.get("X-Powered-By", "")
    if powered_by:
        results.append(make_result(
            module="Info Disclosure",
            check_name="X-Powered-By Header",
            status="FAIL",
            severity="MEDIUM",
            description=f"Header X-Powered-By lộ công nghệ: '{powered_by}'",
            fix="Xóa header X-Powered-By trong cấu hình server/framework"
        ))
    else:
        results.append(make_result(
            module="Info Disclosure",
            check_name="X-Powered-By Header",
            status="PASS",
            severity="INFO",
            description="Không có header X-Powered-By — tốt"
        ))

    # ── Kiểm tra các header tiết lộ thông tin khác ──
    extra_info_headers = [
        ("X-AspNet-Version", "ASP.NET version"),
        ("X-AspNetMvc-Version", "ASP.NET MVC version"),
        ("X-Generator", "CMS/Generator"),
    ]
    for header_name, desc in extra_info_headers:
        value = response.headers.get(header_name, "")
        if value:
            results.append(make_result(
                module="Info Disclosure",
                check_name=f"{header_name} Header",
                status="FAIL",
                severity="MEDIUM",
                description=f"Header {header_name} lộ {desc}: '{value}'",
                fix=f"Xóa header {header_name} trong cấu hình server"
            ))

    return results
