"""
Module 2: Kiểm tra Information Disclosure (Thông tin bị lộ)
Phát hiện các header lộ thông tin về server, framework, phiên bản phần mềm.
"""

import re
from source.utils import make_result


def check_info_disclosure(response):
    """
    Kiểm tra các thông tin server bị lộ trong headers.
    """
    results = []

    # ── Kiểm tra header "Server" ──
    server = response.headers.get("Server", "")
    if server:
        version_pattern = re.compile(r"(\d+\.\d+[\d.]*)")
        version_match = version_pattern.search(server)
        
        if version_match:
            version = version_match.group(1)
            tech = server.split('/')[0] if '/' in server else server.split(' ')[0]
            confidence = 90 if version.count('.') >= 2 else 80
            
            results.append(make_result(
                module="Info Disclosure",
                check_name="Server Header",
                status="FAIL",
                severity="MEDIUM",
                what_found=f"Header 'Server' tiết lộ phiên bản phần mềm chính xác: '{server}'",
                confidence=confidence,
                confidence_reason=f"Phát hiện pattern phiên bản '{version}' trong chuỗi ký tự",
                exposure_detail={
                    "leaked_data": [f"Phần mềm: {tech}", f"Phiên bản: {version}"],
                    "extra_intel": f"CVE Search: https://www.cvedetails.com/google-search-results.php?q={tech}+{version}",
                    "attack_surface": "Attacker có thể tra cứu các lỗ hổng (CVE) đã biết cho phiên bản này để thực hiện exploit."
                },
                manual_test=[
                    {"step": 1, "action": "Kiểm tra header Server", "command": f"curl -I {response.url}", "expected": f"Dòng 'Server: {server}' xuất hiện"}
                ]
            ))
        else:
            results.append(make_result(
                module="Info Disclosure",
                check_name="Server Header",
                status="WARN",
                severity="LOW",
                what_found=f"Header 'Server' tồn tại nhưng không lộ phiên bản chi tiết: '{server}'",
                confidence=70,
                confidence_reason="Header tồn tại nhưng chỉ chứa tên phần mềm chung chung",
                exposure_detail={
                    "leaked_data": [f"Phần mềm: {server}"],
                    "extra_intel": "Thông tin hạn chế, khó tìm lỗ hổng cụ thể.",
                    "attack_surface": "Giảm bớt khả năng tấn công trúng đích nhưng vẫn xác định được loại web server."
                }
            ))
    else:
        results.append(make_result(
            module="Info Disclosure",
            check_name="Server Header",
            status="PASS",
            severity="INFO",
            what_found="Không tìm thấy header Server.",
            confidence=100,
            confidence_reason="Header vắng mặt hoàn toàn"
        ))

    # ── Kiểm tra header "X-Powered-By" ──
    powered_by = response.headers.get("X-Powered-By", "")
    if powered_by:
        results.append(make_result(
            module="Info Disclosure",
            check_name="X-Powered-By Header",
            status="FAIL",
            severity="MEDIUM",
            what_found=f"Header 'X-Powered-By' lộ công nghệ phía backend: '{powered_by}'",
            confidence=95,
            confidence_reason="Header được gửi trực tiếp bởi framework/language",
            exposure_detail={
                "leaked_data": [f"Công nghệ: {powered_by}"],
                "extra_intel": "",
                "attack_surface": "Attacker xác định được ngôn ngữ lập trình hoặc framework để thu hẹp phạm vi tấn công (vd: PHP, ASP.NET, Express)."
            }
        ))
    else:
        results.append(make_result(
            module="Info Disclosure",
            check_name="X-Powered-By Header",
            status="PASS",
            severity="INFO",
            what_found="Không có header X-Powered-By."
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
                what_found=f"Header '{header_name}' lộ {desc}: '{value}'",
                confidence=95,
                exposure_detail={
                    "leaked_data": [value],
                    "extra_intel": "",
                    "attack_surface": f"Tiết lộ thông tin về {desc} giúp attacker tìm lỗ hổng đặc thù của CMS/Framework."
                }
            ))

    return results
