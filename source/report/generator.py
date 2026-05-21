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
from source.utils import get_score_label


def generate_html_report(target, results, score, duration, output_file):
    """
    Tạo file báo cáo HTML (Scan Intelligence Report).
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")

    # Phân loại kết quả theo severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    grouped_results = {s: [] for s in severity_order}
    for r in results:
        grouped_results[r["severity"]].append(r)

    cards_html = ""
    for sev in severity_order:
        items = grouped_results[sev]
        if not items: continue
        
        cards_html += f"<h2 class='sev-title {sev.lower()}'>{sev} Findings</h2>"
        
        for r in items:
            status_cls = r["status"].lower()
            conf = r.get("confidence", 0)
            conf_reason = html_module.escape(r.get("confidence_reason", ""))
            what = html_module.escape(r.get("what_found", ""))
            module = html_module.escape(r["module"])
            check = html_module.escape(r["check"])
            
            # Exposure Detail
            exp = r.get("exposure_detail", {})
            leaked = exp.get("leaked_data", [])
            intel = html_module.escape(exp.get("extra_intel", ""))
            surface = html_module.escape(exp.get("attack_surface", ""))
            
            exp_html = ""
            if leaked or intel or surface:
                leaked_list = "".join([f"<li><code>{html_module.escape(str(l))}</code></li>" for l in leaked])
                leaked_html = f"<b>Dữ liệu lộ:</b><ul>{leaked_list}</ul>" if leaked else ""
                exp_html = f"""
                <details class="exp-details">
                    <summary>🔍 Chi tiết lộ & Intelligence</summary>
                    <div class="exp-content">
                        {leaked_html}
                        {f'<p><b>Thông tin thêm:</b> {intel}</p>' if intel else ''}
                        {f'<p><b>Attack Surface:</b> {surface}</p>' if surface else ''}
                    </div>
                </details>
                """

            # Manual Test
            manual = r.get("manual_test", [])
            manual_html = ""
            if manual:
                steps = ""
                for s in manual:
                    steps += f"""
                    <div class="step">
                        <div class="step-head">Bước {s['step']}: {html_module.escape(s['action'])}</div>
                        <div class="step-cmd">
                            <code>{html_module.escape(s['command'])}</code>
                            <button onclick="copyCmd(this)">Sao chép</button>
                        </div>
                        <div class="step-exp">Kỳ vọng: <i>{html_module.escape(s['expected'])}</i></div>
                    </div>
                    """
                manual_html = f"""
                <details class="manual-details">
                    <summary>🛠️ Xác minh thủ công ({len(manual)} bước)</summary>
                    <div class="manual-content">{steps}</div>
                </details>
                """

            cards_html += f"""
            <div class="card {status_cls}">
                <div class="card-header">
                    <span class="mod-name">[{module}] {check}</span>
                    <span class="conf-badge" title="{conf_reason}">Confidence: {conf}%</span>
                </div>
                <div class="card-body">
                    <p class="what-found">{what}</p>
                    {exp_html}
                    {manual_html}
                </div>
            </div>
            """

    safe_target = html_module.escape(target)

    html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>WebSec Intelligence Report — {safe_target}</title>
<style>
  :root {{ --critical: #c0392b; --high: #e74c3c; --medium: #e67e22; --low: #f39c12; --info: #3498db; --pass: #27ae60; }}
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #2c3e50; background: #f9f9f9; }}
  h1 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
  .meta {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; font-size: 0.9em; line-height: 1.6; }}
  .score-bar {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
  .score-val {{ font-size: 3em; font-weight: bold; color: var(--info); }}
  .summary {{ display: flex; gap: 10px; margin-bottom: 30px; justify-content: center; }}
  .badge {{ padding: 8px 15px; border-radius: 20px; font-weight: bold; color: white; }}
  .bg-pass {{ background: var(--pass); }} .bg-fail {{ background: var(--high); }} .bg-warn {{ background: var(--medium); }}
  
  .sev-title {{ margin-top: 40px; padding: 5px 15px; border-radius: 4px; color: white; text-transform: uppercase; font-size: 1em; letter-spacing: 1px; }}
  .critical {{ background: var(--critical); }} .high {{ background: var(--high); }} .medium {{ background: var(--medium); }} .low {{ background: var(--low); }} .info {{ background: var(--info); }}
  
  .card {{ background: white; border-radius: 8px; margin: 15px 0; border-left: 5px solid #ccc; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }}
  .card.fail {{ border-left-color: var(--high); }}
  .card.warn {{ border-left-color: var(--medium); }}
  .card.pass {{ border-left-color: var(--pass); }}
  
  .card-header {{ background: #fcfcfc; padding: 12px 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }}
  .mod-name {{ font-weight: bold; font-size: 1.1em; }}
  .conf-badge {{ font-size: 0.75em; background: #eee; padding: 2px 8px; border-radius: 10px; color: #666; cursor: help; }}
  
  .card-body {{ padding: 20px; }}
  .what-found {{ font-size: 1.05em; line-height: 1.5; margin-bottom: 15px; }}
  
  details {{ background: #f8f9fa; border-radius: 6px; margin-top: 10px; border: 1px solid #eee; }}
  summary {{ padding: 10px 15px; cursor: pointer; font-weight: bold; font-size: 0.9em; outline: none; }}
  .exp-content, .manual-content {{ padding: 15px; border-top: 1px solid #eee; font-size: 0.9em; }}
  
  .step {{ margin-bottom: 15px; padding-left: 10px; border-left: 2px solid #ddd; }}
  .step-head {{ font-weight: bold; margin-bottom: 5px; }}
  .step-cmd {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; margin: 8px 0; }}
  .step-cmd code {{ font-family: 'Consolas', monospace; word-break: break-all; }}
  .step-cmd button {{ background: #34495e; border: none; color: white; padding: 4px 8px; border-radius: 3px; cursor: pointer; font-size: 0.8em; }}
  .step-cmd button:hover {{ background: #4e6a85; }}
  .step-exp {{ color: #7f8c8d; font-size: 0.85em; }}
  
  .disclaimer {{ margin-top: 60px; padding: 20px; background: #fff5f5; border: 1px solid #ffcccc; border-radius: 8px; font-size: 0.85em; text-align: center; }}
</style>
<script>
function copyCmd(btn) {{
    var cmd = btn.parentNode.querySelector('code').innerText;
    navigator.clipboard.writeText(cmd).then(() => {{
        var oldText = btn.innerText;
        btn.innerText = "Đã chép!";
        btn.style.background = "#27ae60";
        setTimeout(() => {{ btn.innerText = oldText; btn.style.background = "#34495e"; }}, 1500);
    }});
}}
</script>
</head>
<body>
<h1>🔍 WebSec Intelligence Report</h1>
<div class="meta">
  <b>🎯 Mục tiêu:</b> {safe_target}<br>
  <b>🕒 Thời gian quét:</b> {now}<br>
  <b>⏱️ Thời lượng:</b> {duration:.1f} giây
</div>

<div class="score-bar">
  <div style="font-size: 0.9em; color: #666;">Security Score</div>
  <div class="score-val">{score}/100</div>
  <div style="font-weight: bold;">{get_score_label(score)}</div>
</div>

<div class="summary">
  <div class="badge bg-pass">✅ PASS: {passed}</div>
  <div class="badge bg-fail">❌ FAIL: {failed}</div>
  <div class="badge bg-warn">⚠️ WARN: {warned}</div>
</div>

{cards_html}

<div class="disclaimer">
  ⚠️ <b>BÁO CÁO CỰC KỲ NHẠY CẢM:</b> Thông tin trong báo cáo này được thiết kế để phục vụ việc xác minh lỗ hổng thủ công. <br>
  TUYỆT ĐỐI không chia sẻ báo cáo này cho bên không liên quan. <br>
  <i>Chỉ sử dụng cho mục đích bảo mật hợp pháp.</i>
</div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_json_report(target, results, score, duration, output_file):
    """
    Tạo file báo cáo JSON.
    """
    report = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "duration_seconds": round(duration, 2),
        "score": score,
        "score_label": get_score_label(score),
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
    In tóm tắt kết quả ra terminal (Intelligence Summary).
    """
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")

    print("\n" + "=" * 60)
    print(f"  WEBSEC INTELLIGENCE REPORT: {target}")
    print("=" * 60)
    print(f"  Security Score: {score}/100 — {get_score_label(score)}")

    if HAS_COLORAMA:
        pass_str = f"{Fore.GREEN}✅ PASS: {passed}{Style.RESET_ALL}"
        fail_str = f"{Fore.RED}❌ FAIL: {failed}{Style.RESET_ALL}"
        warn_str = f"{Fore.YELLOW}⚠️  WARN: {warned}{Style.RESET_ALL}"
        print(f"  {pass_str}   {fail_str}   {warn_str}")
    else:
        print(f"  ✅ PASS: {passed}   ❌ FAIL: {failed}   ⚠️  WARN: {warned}")

    print(f"  Thời gian: {duration:.1f}s")
    print("-" * 60)

    issues = [r for r in results if r["status"] in ("FAIL", "WARN")]
    issues.sort(key=lambda x: list(SEVERITY_SCORE.keys()).index(x["severity"]))

    if issues:
        print("  FINDINGS & EXPOSURES:")
        for r in issues:
            conf = r.get("confidence", 0)
            msg = r.get("what_found", r.get("description", ""))
            
            if HAS_COLORAMA:
                if r["severity"] == "CRITICAL":
                    icon = f"{Fore.RED}🔴{Style.RESET_ALL}"
                    sev = f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
                elif r["severity"] == "HIGH":
                    icon = f"{Fore.RED}🟠{Style.RESET_ALL}"
                    sev = f"{Fore.RED}HIGH    {Style.RESET_ALL}"
                elif r["severity"] == "MEDIUM":
                    icon = f"{Fore.YELLOW}🟡{Style.RESET_ALL}"
                    sev = f"{Fore.YELLOW}MEDIUM  {Style.RESET_ALL}"
                else:
                    icon = "⚪"
                    sev = f"{r['severity']:8}"
                
                print(f"  {icon} [{sev}] Conf: {conf:>3}% | {msg[:70]}...")
            else:
                icon = "🔴" if r["severity"] == "CRITICAL" else \
                       "🟠" if r["severity"] == "HIGH" else \
                       "🟡" if r["severity"] == "MEDIUM" else "⚪"
                print(f"  {icon} [{r['severity']:8}] Conf: {conf:>3}% | {msg[:70]}...")
    else:
        print("  Không phát hiện lộ lọt thông tin nghiêm trọng.")

    print("=" * 60)
