"""
Module 3: Kiểm tra HTTPS / TLS Configuration
Kiểm tra: có HTTPS không, HTTP redirect sang HTTPS không, certificate còn hạn không,
TLS version có an toàn không.
"""

import ssl
import socket
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

from source.config import CERT_EXPIRY_WARNING_DAYS, DEFAULT_TLS_PORT
from source.utils import make_result, safe_get, get_base_url, logger


def check_https(url, verify_ssl=True):
    """
    Kiểm tra cấu hình HTTPS đầy đủ.
    """
    results = []
    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0]

    # ── Kiểm tra có dùng HTTPS không ──
    if parsed.scheme == "http":
        results.append(make_result(
            module="HTTPS",
            check_name="HTTPS Enabled",
            status="FAIL",
            severity="HIGH",
            what_found="Website đang sử dụng giao thức HTTP không mã hóa.",
            confidence=100,
            confidence_reason="Scheme của URL yêu cầu là 'http'",
            exposure_detail={
                "leaked_data": [],
                "extra_intel": "Protocol: HTTP/1.1",
                "attack_surface": "Toàn bộ dữ liệu truyền tải (mật khẩu, session cookie, nội dung trang) có thể bị chặn thu và đọc bởi bất kỳ ai trong cùng mạng (nút mạng trung gian, wifi công cộng)."
            },
            manual_test=[
                {"step": 1, "action": "Kiểm tra protocol bằng curl", "command": f"curl -I {url}", "expected": "Dòng đầu tiên chứa 'HTTP/1.1' hoặc 'HTTP/2' mà không có redirect sang HTTPS"}
            ]
        ))
        return results

    results.append(make_result(
        module="HTTPS",
        check_name="HTTPS Enabled",
        status="PASS",
        severity="INFO",
        what_found="Website sử dụng giao thức HTTPS.",
        confidence=100
    ))

    # ── Kiểm tra HTTP redirect sang HTTPS ──
    results.extend(_check_http_redirect(url, verify_ssl=verify_ssl))

    # ── Kiểm tra certificate + TLS version ──
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, DEFAULT_TLS_PORT))
        cert = conn.getpeercert()
        tls_version = conn.version()
        conn.close()

        if tls_version and tls_version in ("TLSv1", "TLSv1.1"):
            results.append(make_result(
                module="HTTPS",
                check_name="TLS Version",
                status="FAIL",
                severity="HIGH",
                what_found=f"Server đang hỗ trợ giao thức {tls_version} (đã lỗi thời).",
                confidence=99,
                confidence_reason="Xác nhận trực tiếp qua TLS handshake",
                exposure_detail={
                    "leaked_data": [f"Giao thức: {tls_version}"],
                    "extra_intel": "",
                    "attack_surface": "Các phiên bản TLS cũ có nhiều lỗ hổng bảo mật đã biết (vd: BEAST, POODLE) cho phép attacker giải mã traffic."
                },
                manual_test=[
                    {"step": 1, "action": "Kiểm tra TLS version mạnh", "command": f"openssl s_client -connect {hostname}:443 -{tls_version.lower().replace('v', '')}", "expected": "Kết nối thành công (Handshake diễn ra)"}
                ]
            ))
        elif tls_version:
            results.append(make_result(
                module="HTTPS",
                check_name="TLS Version",
                status="PASS",
                severity="INFO",
                what_found=f"Server sử dụng giao thức an toàn: {tls_version}",
                confidence=100
            ))

        # Ngày hết hạn
        expire_str = cert.get("notAfter", "")
        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expire_date - datetime.now(timezone.utc)).days

        if days_left < 0:
            results.append(make_result(
                module="HTTPS",
                check_name="Certificate Expiry",
                status="FAIL",
                severity="CRITICAL",
                what_found=f"SSL Certificate đã hết hạn từ ngày {expire_str} ({abs(days_left)} ngày trước).",
                confidence=99,
                confidence_reason="Ngày hết hạn trích xuất trực tiếp từ certificate của server",
                exposure_detail={
                    "leaked_data": [f"Expired: {expire_str}"],
                    "extra_intel": f"Issuer: {cert.get('issuer')}",
                    "attack_surface": "Trình duyệt sẽ hiển thị cảnh báo đỏ cực mạnh, người dùng có thể bị tấn công mạo danh hoặc chặn traffic do cert không còn tin cậy."
                },
                manual_test=[
                    {"step": 1, "action": "Kiểm tra cert bằng openssl", "command": f"openssl s_client -connect {hostname}:443 | openssl x509 -noout -dates", "expected": f"notAfter={expire_str}"}
                ]
            ))
        elif days_left < CERT_EXPIRY_WARNING_DAYS:
            results.append(make_result(
                module="HTTPS",
                check_name="Certificate Expiry",
                status="WARN",
                severity="MEDIUM",
                what_found=f"SSL Certificate sắp hết hạn: còn {days_left} ngày (hết hạn vào {expire_str}).",
                confidence=99,
                exposure_detail={
                    "leaked_data": [f"Expires: {expire_str}"],
                    "extra_intel": "",
                    "attack_surface": "Website sẽ bị gián đoạn hoạt động ngay khi chứng chỉ hết hạn."
                }
            ))

    except Exception as e:
        results.append(make_result(
            module="HTTPS",
            check_name="Certificate Valid",
            status="FAIL",
            severity="HIGH",
            what_found=f"Lỗi khi xác thực chứng chỉ SSL/TLS: {type(e).__name__}",
            confidence=90,
            exposure_detail={
                "leaked_data": [str(e)],
                "extra_intel": "",
                "attack_surface": "Kết nối không an toàn, có thể bị giả mạo hoặc cert không khớp domain."
            }
        ))

    return results


def _check_http_redirect(url, verify_ssl=True):
    """
    Kiểm tra xem HTTP có tự redirect sang HTTPS không.
    """
    results = []
    parsed = urlparse(url)
    http_url = f"http://{parsed.netloc}"

    try:
        r = safe_get(http_url, verify_ssl=verify_ssl, allow_redirects=False)
        if r is None: return results

        if r.status_code in (301, 302, 307, 308):
            location = r.headers.get("Location", "")
            if location.startswith("https://"):
                results.append(make_result(
                    module="HTTPS",
                    check_name="HTTP to HTTPS Redirect",
                    status="PASS",
                    severity="INFO",
                    what_found=f"HTTP tự động chuyển hướng sang HTTPS ({r.status_code} → {location})",
                    confidence=100
                ))
            else:
                results.append(make_result(
                    module="HTTPS",
                    check_name="HTTP to HTTPS Redirect",
                    status="WARN",
                    severity="MEDIUM",
                    what_found=f"HTTP chuyển hướng nhưng không sang giao thức HTTPS (đến: {location})",
                    confidence=95,
                    exposure_detail={
                        "leaked_data": [f"Redirect Location: {location}"],
                        "extra_intel": f"Status code: {r.status_code}",
                        "attack_surface": "Người dùng vẫn có thể bị kẹt ở giao thức không an toàn nếu location không phải HTTPS."
                    }
                ))
        else:
            results.append(make_result(
                module="HTTPS",
                check_name="HTTP to HTTPS Redirect",
                status="FAIL",
                severity="MEDIUM",
                what_found=f"HTTP không tự động chuyển hướng sang HTTPS (Status code: {r.status_code})",
                confidence=95,
                exposure_detail={
                    "leaked_data": [],
                    "extra_intel": f"Status: {r.status_code}",
                    "attack_surface": "Người dùng hoàn toàn có thể truy cập website qua HTTP, tạo điều kiện cho tấn công đánh cắp dữ liệu trên đường truyền."
                },
                manual_test=[
                    {"step": 1, "action": "Gửi request HTTP", "command": f"curl -I {http_url}", "expected": "Status code 200 thay vì 301/302"}
                ]
            ))
    except Exception:
        pass

    return results
