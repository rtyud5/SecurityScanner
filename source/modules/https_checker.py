"""
Module 3: Kiểm tra HTTPS / TLS Configuration
Kiểm tra: có HTTPS không, HTTP redirect sang HTTPS không, certificate còn hạn không,
TLS version có an toàn không.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from source.config import CERT_EXPIRY_WARNING_DAYS, DEFAULT_TLS_PORT
from source.utils import make_result, safe_get, get_base_url, logger


def check_https(url):
    """
    Kiểm tra cấu hình HTTPS đầy đủ:
    1. Website có dùng HTTPS không
    2. HTTP có redirect sang HTTPS không
    3. Certificate còn hạn không
    4. TLS version có an toàn không

    Args:
        url: URL đã được chuẩn hóa

    Returns:
        list[dict]: Danh sách ScanResult
    """
    results = []
    parsed = urlparse(url)

    # ── Kiểm tra có dùng HTTPS không ──
    if parsed.scheme == "http":
        results.append(make_result(
            module="HTTPS",
            check_name="HTTPS Enabled",
            status="FAIL",
            severity="HIGH",
            description="Website không dùng HTTPS — dữ liệu truyền đi không được mã hóa",
            fix="Cài SSL certificate và chuyển toàn bộ traffic sang HTTPS"
        ))
        return results  # Không cần kiểm tra thêm nếu không có HTTPS

    results.append(make_result(
        module="HTTPS",
        check_name="HTTPS Enabled",
        status="PASS",
        severity="INFO",
        description="Website dùng HTTPS"
    ))

    # ── Kiểm tra HTTP redirect sang HTTPS ──
    results.extend(_check_http_redirect(url))

    # ── Kiểm tra certificate + TLS version ──
    hostname = parsed.netloc.split(":")[0]  # Bỏ port nếu có
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, DEFAULT_TLS_PORT))
        cert = conn.getpeercert()

        # Kiểm tra TLS version
        tls_version = conn.version()
        conn.close()

        if tls_version and tls_version in ("TLSv1", "TLSv1.1"):
            results.append(make_result(
                module="HTTPS",
                check_name="TLS Version",
                status="FAIL",
                severity="HIGH",
                description=f"Server dùng {tls_version} đã bị deprecated (không an toàn)",
                fix="Nâng cấp lên TLS 1.2 hoặc TLS 1.3"
            ))
        elif tls_version:
            results.append(make_result(
                module="HTTPS",
                check_name="TLS Version",
                status="PASS",
                severity="INFO",
                description=f"Server dùng {tls_version}"
            ))

        # Lấy ngày hết hạn — dùng UTC để so sánh chính xác
        expire_str = cert.get("notAfter", "")
        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        expire_date = expire_date.replace(tzinfo=timezone.utc)
        days_left = (expire_date - datetime.now(timezone.utc)).days

        if days_left < 0:
            results.append(make_result(
                module="HTTPS",
                check_name="Certificate Expiry",
                status="FAIL",
                severity="CRITICAL",
                description=f"SSL Certificate đã hết hạn {abs(days_left)} ngày trước!",
                fix="Gia hạn SSL certificate ngay lập tức"
            ))
        elif days_left < CERT_EXPIRY_WARNING_DAYS:
            results.append(make_result(
                module="HTTPS",
                check_name="Certificate Expiry",
                status="WARN",
                severity="MEDIUM",
                description=f"SSL Certificate sắp hết hạn: còn {days_left} ngày",
                fix="Lên kế hoạch gia hạn certificate sớm"
            ))
        else:
            results.append(make_result(
                module="HTTPS",
                check_name="Certificate Expiry",
                status="PASS",
                severity="INFO",
                description=f"SSL Certificate còn hạn: {days_left} ngày"
            ))

    except ssl.SSLError as e:
        results.append(make_result(
            module="HTTPS",
            check_name="Certificate Valid",
            status="FAIL",
            severity="HIGH",
            description=f"Lỗi SSL Certificate: {str(e)}",
            fix="Kiểm tra và cài lại SSL certificate đúng cách"
        ))
    except Exception:
        results.append(make_result(
            module="HTTPS",
            check_name="Certificate Valid",
            status="WARN",
            severity="LOW",
            description="Không thể kiểm tra certificate (có thể do timeout)"
        ))

    return results


def _check_http_redirect(url):
    """
    Kiểm tra xem HTTP có tự redirect sang HTTPS không.
    Nếu website dùng HTTPS, thử truy cập qua HTTP xem có redirect không.

    Args:
        url: URL HTTPS gốc

    Returns:
        list[dict]: Danh sách ScanResult
    """
    results = []
    parsed = urlparse(url)

    # Tạo URL HTTP tương ứng
    http_url = f"http://{parsed.netloc}"

    try:
        r = safe_get(http_url, allow_redirects=False)
        if r is None:
            return results  # Không thể kiểm tra, bỏ qua

        if r.status_code in (301, 302, 307, 308):
            location = r.headers.get("Location", "")
            if location.startswith("https://"):
                results.append(make_result(
                    module="HTTPS",
                    check_name="HTTP to HTTPS Redirect",
                    status="PASS",
                    severity="INFO",
                    description=f"HTTP tự redirect sang HTTPS ({r.status_code} → {location})"
                ))
            else:
                results.append(make_result(
                    module="HTTPS",
                    check_name="HTTP to HTTPS Redirect",
                    status="WARN",
                    severity="MEDIUM",
                    description=f"HTTP redirect nhưng không sang HTTPS (→ {location})",
                    fix="Cấu hình redirect từ HTTP sang HTTPS"
                ))
        else:
            results.append(make_result(
                module="HTTPS",
                check_name="HTTP to HTTPS Redirect",
                status="FAIL",
                severity="MEDIUM",
                description=f"HTTP không redirect sang HTTPS (status: {r.status_code})",
                fix="Thêm redirect rule: HTTP → HTTPS (301 permanent redirect)"
            ))
    except Exception:
        logger.debug("Không thể kiểm tra HTTP redirect")

    return results
