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
    """
    all_results = []

    # Gửi request ban đầu
    print("  [1/7] connection check")
    response = safe_get(url, verify_ssl=verify_ssl)

    if response is None:
        print(f"\n  [ERROR] could not connect to {url}")
        return None

    # Chạy từng module
    print("  [2/7] http security headers")
    all_results.extend(check_headers(response))

    print("  [3/7] information disclosure")
    all_results.extend(check_info_disclosure(response))

    print("  [4/7] https / tls")
    all_results.extend(check_https(url, verify_ssl=verify_ssl))

    print("  [5/7] sensitive path discovery", end="", flush=True)
    path_results = check_sensitive_paths(url, verify_ssl=verify_ssl)
    all_results.extend(path_results)
    # Tìm số lượng FAIL trong path scanner để báo cáo count
    path_count = sum(1 for r in path_results if r["status"] == "FAIL")
    print(f"  ->  {path_count} paths")

    print("  [6/7] cookie flags")
    all_results.extend(check_cookies(response))

    print("  [7/7] cors + robots.txt")
    all_results.extend(check_cors(url, verify_ssl=verify_ssl))
    all_results.extend(check_robots(url, verify_ssl=verify_ssl))

    return all_results


def main():
    """Entry point CLI."""

    # Disclaimer
    print("=" * 60)
    print("  WebSec Scanner — Educational Audit Tool")
    print("  Authorized testing only")
    print("=" * 60)

    # Đọc tham số CLI
    parser = argparse.ArgumentParser(
        description="WebSec Scanner — Security Audit Engine"
    )
    parser.add_argument("--url", required=True,
                        help="Target URL")
    parser.add_argument("--output", default="report.html",
                        help="HTML report path")
    parser.add_argument("--json", default="report.json",
                        help="JSON export path")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL verification")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose logging")
    args = parser.parse_args()

    # Cấu hình logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="  [%(levelname)s] %(message)s")

    verify_ssl = not args.no_verify
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = normalize_url(args.url)

    # Validate URL
    if not validate_url(url):
        print(f"\n  [ERROR] invalid url format: {url}")
        return

    print(f"\n  target: {url}")

    # Chạy scan
    start_time = datetime.now()
    all_results = run_scan(url, verify_ssl=verify_ssl)

    if all_results is None:
        return

    # Tính điểm và xuất báo cáo
    duration = (datetime.now() - start_time).total_seconds()
    score = calculate_score(all_results)

    print("\n  generating report...")
    generate_html_report(url, all_results, score, duration, args.output)
    generate_json_report(url, all_results, score, duration, args.json)

    print_summary(url, all_results, score, duration)
    print(f"\n  Full report : {args.output}")
    print(f"  JSON export : {args.json}\n")
