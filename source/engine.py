"""
ScanEngine — Điều phối tất cả modules quét bảo mật.
Nhận URL, chạy 7 module, thu thập kết quả, tính điểm.

run_scan()  → logic quét thuần, Flask/UI có thể gọi trực tiếp
main()      → chỉ parse CLI, gọi run_scan(), gọi report
"""

import logging
import argparse
import urllib3
from datetime import datetime

from source.config import SEVERITY_SCORE
from source.utils import normalize_url, validate_url, safe_get, get_score_label

from source.modules.header_scanner import check_headers
from source.modules.info_scanner import check_info_disclosure
from source.modules.https_checker import check_https
from source.modules.path_scanner import check_sensitive_paths
from source.modules.cookie_checker import check_cookies
from source.modules.cors_checker import check_cors
from source.modules.robots_parser import check_robots

from source.report.generator import (
    generate_html_report, generate_json_report, print_summary
)


def calculate_score(results):
    """Tính Security Score từ 0-100 dựa trên các vấn đề tìm được"""
    score = 100
    for r in results:
        if r["status"] == "FAIL":
            score -= SEVERITY_SCORE.get(r["severity"], 0)
    return max(0, score)


def run_scan(url, verify_ssl=False):
    """
    Chạy tất cả 7 module quét bảo mật.
    Hàm này chỉ chứa logic quét — không đụng CLI hay report.
    Flask hoặc UI khác có thể import và gọi trực tiếp.

    Args:
        url: URL đã được chuẩn hóa
        verify_ssl: Có kiểm tra SSL certificate không

    Returns:
        list[dict]: Danh sách tất cả ScanResult từ 7 modules, hoặc None nếu lỗi kết nối
    """
    all_results = []

    # Gửi request ban đầu
    print("  [1/7] Kiểm tra kết nối...")
    response = safe_get(url, verify_ssl=verify_ssl)

    if response is None:
        print(f"\n  ❌ Không thể kết nối tới {url}")
        print("  Kiểm tra lại URL và kết nối mạng.")
        return None

    # Chạy từng module
    print("  [2/7] Kiểm tra HTTP Security Headers...")
    all_results.extend(check_headers(response))

    print("  [3/7] Kiểm tra Information Disclosure...")
    all_results.extend(check_info_disclosure(response))

    print("  [4/7] Kiểm tra HTTPS/TLS...")
    all_results.extend(check_https(url))

    print("  [5/7] Quét đường dẫn nhạy cảm...")
    all_results.extend(check_sensitive_paths(url))

    print("  [6/7] Kiểm tra Cookie flags...")
    all_results.extend(check_cookies(response))

    print("  [7/7] Kiểm tra CORS & Robots.txt...")
    all_results.extend(check_cors(url))
    all_results.extend(check_robots(url))

    return all_results


def main():
    """Entry point CLI — chỉ parse argument, gọi run_scan(), gọi report."""

    # Disclaimer
    print("=" * 55)
    print("  WebSec Scanner — Công cụ học tập")
    print("  Chỉ dùng trên website bạn được phép kiểm tra!")
    print("=" * 55)

    # Đọc tham số CLI
    parser = argparse.ArgumentParser(
        description="WebSec Scanner — Quét bảo mật website cơ bản"
    )
    parser.add_argument("--url", required=True,
                        help="URL cần quét (vd: https://example.com)")
    parser.add_argument("--output", default="report.html",
                        help="Tên file báo cáo HTML")
    parser.add_argument("--json", default="report.json",
                        help="Tên file báo cáo JSON")
    parser.add_argument("--no-verify", action="store_true",
                        help="Tắt kiểm tra SSL certificate (dùng cho self-signed certs)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Hiện thông tin debug chi tiết")
    args = parser.parse_args()

    # Cấu hình logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="  [%(levelname)s] %(message)s")

    # Tắt cảnh báo SSL nếu --no-verify
    verify_ssl = not args.no_verify
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = normalize_url(args.url)

    # Validate URL
    if not validate_url(url):
        print(f"\n  ❌ URL không hợp lệ: {url}")
        print("  Ví dụ đúng: https://example.com")
        return

    print(f"\n  Đang quét: {url}")
    print("  Vui lòng chờ...\n")

    # Chạy scan
    start_time = datetime.now()
    all_results = run_scan(url, verify_ssl=verify_ssl)

    if all_results is None:
        return  # Không thể kết nối

    # Tính điểm và xuất báo cáo
    duration = (datetime.now() - start_time).total_seconds()
    score = calculate_score(all_results)

    print("\n  Đang tạo báo cáo...")
    generate_html_report(url, all_results, score, duration, args.output)
    generate_json_report(url, all_results, score, duration, args.json)

    print_summary(url, all_results, score, duration)
    print(f"\n  📄 Báo cáo HTML: {args.output}")
    print(f"  📋 Báo cáo JSON: {args.json}\n")
