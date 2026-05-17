"""
Report Generator — Tạo báo cáo HTML, JSON, và terminal output.
Sử dụng colorama cho terminal output có màu.
"""

import json
import html as html_module
from datetime import datetime

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

from source.config import SEVERITY_SCORE


def _get_score_label(score):
    """Trả về nhãn đánh giá dựa trên điểm"""
    if score >= 80:
        return "TỐT 🟢"
    if score >= 60:
        return "TRUNG BÌNH 🟡"
    if score >= 40:
        return "KÉM 🟠"
    return "NGUY HIỂM 🔴"


def generate_html_report(target, results, score, duration, output_file):
    """
    Tạo file báo cáo HTML đọc được trên mọi trình duyệt (CSS inline).
    Dữ liệu được escape bằng html.escape() để tránh XSS.

    Args:
        target: URL đã quét
        results: Danh sách ScanResult
        score: Điểm bảo mật 0-100
        duration: Thời gian quét (giây)
        output_file: Đường dẫn file HTML output
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")

    # Màu cho từng severity
    severity_color = {
        "CRITICAL": "#c0392b", "HIGH": "#e74c3c",
        "MEDIUM": "#e67e22", "LOW": "#f39c12", "INFO": "#27ae60"
    }
    status_color = {
        "PASS": "#27ae60", "FAIL": "#e74c3c",
        "WARN": "#e67e22", "INFO": "#3498db"
    }

    rows = ""
    for r in sorted(results, key=lambda x: list(SEVERITY_SCORE.keys()).index(x["severity"])):
        sc = status_color.get(r["status"], "#333")
        svc = severity_color.get(r["severity"], "#333")
        # Escape HTML để tránh XSS từ dữ liệu response headers
        safe_module = html_module.escape(str(r['module']))
        safe_check = html_module.escape(str(r['check']))
        safe_status = html_module.escape(str(r['status']))
        safe_severity = html_module.escape(str(r['severity']))
        safe_desc = html_module.escape(str(r['description']))
        safe_fix = html_module.escape(str(r.get('fix', '')))
        fix_html = f"<br><small><b>Cách sửa:</b> {safe_fix}</small>" if r.get("fix") else ""
        rows += f"""
        <tr>
            <td>{safe_module}</td>
            <td>{safe_check}</td>
            <td style="color:{sc};font-weight:bold">{safe_status}</td>
            <td style="color:{svc};font-weight:bold">{safe_severity}</td>
            <td>{safe_desc}{fix_html}</td>
        </tr>"""

    safe_target = html_module.escape(target)

    html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>WebSec Scanner Report — {safe_target}</title>
<style>
  body {{ font-family: sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; color: #333; }}
  h1 {{ color: #2c3e50; }}
  .meta {{ color: #666; font-size: 0.9em; margin-bottom: 24px; }}
  .score {{ font-size: 2.5em; font-weight: bold; margin: 20px 0 8px; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 32px; }}
  .badge {{ padding: 10px 20px; border-radius: 8px; font-weight: bold; font-size: 1.1em; }}
  .pass {{ background: #d5f5e3; color: #1e8449; }}
  .fail {{ background: #fadbd8; color: #922b21; }}
  .warn {{ background: #fdebd0; color: #935116; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:hover {{ background: #f8f9fa; }}
  .disclaimer {{ margin-top: 40px; padding: 16px; background: #fef9e7; border-left: 4px solid #f39c12; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>🔍 WebSec Scanner Report</h1>
<div class="meta">
  <b>Mục tiêu:</b> {safe_target}<br>
  <b>Thời gian quét:</b> {now}<br>
  <b>Thời lượng:</b> {duration:.1f} giây
</div>

<div class="score">Security Score: {score}/100 — {_get_score_label(score)}</div>

<div class="summary">
  <div class="badge pass">✅ PASS: {passed}</div>
  <div class="badge fail">❌ FAIL: {failed}</div>
  <div class="badge warn">⚠️ WARN: {warned}</div>
</div>

<table>
  <tr>
    <th>Module</th><th>Kiểm tra</th><th>Kết quả</th><th>Mức độ</th><th>Chi tiết</th>
  </tr>
  {rows}
</table>

<div class="disclaimer">
  ⚠️ <b>Disclaimer:</b> Công cụ này chỉ dành cho mục đích học tập và kiểm tra website bạn được phép kiểm tra.
  Không sử dụng để quét website của người khác khi chưa được cho phép.
</div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_json_report(target, results, score, duration, output_file):
    """
    Tạo file báo cáo JSON.

    Args:
        target: URL đã quét
        results: Danh sách ScanResult
        score: Điểm bảo mật 0-100
        duration: Thời gian quét (giây)
        output_file: Đường dẫn file JSON output
    """
    report = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "duration_seconds": round(duration, 2),
        "score": score,
        "score_label": _get_score_label(score),
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r["status"] == "PASS"),
            "failed": sum(1 for r in results if r["status"] == "FAIL"),
            "warned": sum(1 for r in results if r["status"] == "WARN"),
        },
        "results": results
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def print_summary(target, results, score, duration):
    """
    In tóm tắt kết quả ra terminal.
    Sử dụng colorama nếu có để in màu PASS/FAIL/WARN.

    Args:
        target: URL đã quét
        results: Danh sách ScanResult
        score: Điểm bảo mật 0-100
        duration: Thời gian quét (giây)
    """
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")

    print("\n" + "=" * 55)
    print(f"  KẾT QUẢ QUÉT: {target}")
    print("=" * 55)
    print(f"  Security Score: {score}/100 — {_get_score_label(score)}")

    # In số lượng PASS/FAIL/WARN có màu nếu có colorama
    if HAS_COLORAMA:
        pass_str = f"{Fore.GREEN}✅ PASS: {passed}{Style.RESET_ALL}"
        fail_str = f"{Fore.RED}❌ FAIL: {failed}{Style.RESET_ALL}"
        warn_str = f"{Fore.YELLOW}⚠️  WARN: {warned}{Style.RESET_ALL}"
        print(f"  {pass_str}   {fail_str}   {warn_str}")
    else:
        print(f"  ✅ PASS: {passed}   ❌ FAIL: {failed}   ⚠️  WARN: {warned}")

    print(f"  Thời gian: {duration:.1f}s")
    print("-" * 55)

    # Chỉ in các vấn đề FAIL và WARN
    issues = [r for r in results if r["status"] in ("FAIL", "WARN")]
    issues.sort(key=lambda x: list(SEVERITY_SCORE.keys()).index(x["severity"]))

    if issues:
        print("  VẤN ĐỀ TÌM THẤY:")
        for r in issues:
            if HAS_COLORAMA:
                if r["severity"] == "CRITICAL":
                    icon = f"{Fore.RED}🔴{Style.RESET_ALL}"
                    sev = f"{Fore.RED}{r['severity']:8}{Style.RESET_ALL}"
                elif r["severity"] == "HIGH":
                    icon = f"{Fore.RED}🟠{Style.RESET_ALL}"
                    sev = f"{Fore.RED}{r['severity']:8}{Style.RESET_ALL}"
                elif r["severity"] == "MEDIUM":
                    icon = f"{Fore.YELLOW}🟡{Style.RESET_ALL}"
                    sev = f"{Fore.YELLOW}{r['severity']:8}{Style.RESET_ALL}"
                else:
                    icon = "⚪"
                    sev = f"{r['severity']:8}"
                print(f"  {icon} [{sev}] {r['description'][:60]}")
            else:
                icon = "🔴" if r["severity"] == "CRITICAL" else \
                       "🟠" if r["severity"] == "HIGH" else \
                       "🟡" if r["severity"] == "MEDIUM" else "⚪"
                print(f"  {icon} [{r['severity']:8}] {r['description'][:60]}")
    else:
        print("  Không tìm thấy vấn đề nào đáng lo!")

    print("=" * 55)
