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
    Tạo file báo cáo chuyên nghiệp (Burp Suite / Nessus style).
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    passed_count = sum(1 for r in results if r["status"] == "PASS")
    
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = {sev: sum(1 for r in results if r["severity"] == sev and r["status"] == "FAIL") for sev in severity_order}
    
    grouped_results = {s: [] for s in severity_order}
    passed_results = []
    for r in results:
        if r["status"] == "PASS":
            passed_results.append(r)
        else:
            grouped_results[r["severity"]].append(r)

    rating = get_score_label(score)
    
    # CSS & JS content
    styles = """
    :root { --bg: #ffffff; --text: #1a1a1a; --border: #e0e0e0; --header-bg: #1a1a1a; --header-text: #ffffff; }
    body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; font-size: 14px; line-height: 1.5; color: var(--text); background: var(--bg); margin: 0; padding: 0; }
    .container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
    .header-bar { background: var(--header-bg); color: var(--header-text); padding: 10px 20px; font-weight: 600; font-size: 16px; border-bottom: 3px solid #333; }
    
    .meta-box { margin: 30px 0; padding-bottom: 20px; border-bottom: 1px solid var(--border); }
    .score-display { font-size: 20px; font-weight: 600; margin-bottom: 10px; }
    .rating { font-size: 16px; color: #555; }
    
    .summary-table { width: 400px; border-collapse: collapse; margin-top: 20px; font-family: monospace; }
    .summary-table td { padding: 4px 8px; border-bottom: 1px solid #f0f0f0; }
    .summary-table td:last-child { text-align: right; }
    
    .finding-group-title { margin: 40px 0 20px; font-size: 18px; border-left: 4px solid var(--header-bg); padding-left: 12px; }
    
    .card { border: 1px solid var(--border); border-top: none; margin-bottom: 30px; border-radius: 0 0 3px 3px; background: #fff; }
    .card-header { background: var(--header-bg); color: var(--header-text); padding: 8px 15px; display: flex; justify-content: space-between; align-items: center; font-weight: 600; font-size: 13px; }
    .card-header .title { flex-grow: 1; }
    .card-header .conf { font-family: monospace; font-size: 12px; border-left: 1px solid #444; padding-left: 15px; margin-left: 15px; }
    .card-body { padding: 20px; }
    
    /* Severity left borders */
    .card.critical { border-left: 3px solid #cc0000; background: #fdf0f0; }
    .card.high { border-left: 3px solid #cc4400; background: #fdf5f0; }
    .card.medium { border-left: 3px solid #997700; background: #fdfaf0; }
    .card.low { border-left: 3px solid #557700; background: #fafdf0; }
    .card.info { border-left: 3px solid #aaaaaa; background: #f5f5f5; }
    .card.pass { border-left: 3px solid #555555; background: #f5f5f5; }

    .section-title { font-weight: 600; color: #333; margin-top: 15px; margin-bottom: 8px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
    .section-content { margin-left: 10px; margin-bottom: 20px; }
    
    ul { margin: 5px 0; padding-left: 20px; }
    li { margin-bottom: 4px; }
    
    code-block { display: block; background: #fff; border: 1px solid #ddd; padding: 12px; margin: 10px 0; overflow-x: auto; font-family: "SF Mono", "Consolas", monospace; font-size: 13px; white-space: pre-wrap; position: relative; }
    .copy-btn { position: absolute; top: 8px; right: 8px; border: 1px solid #ccc; background: white; font-size: 12px; padding: 2px 8px; cursor: pointer; border-radius: 2px; }
    .copy-btn:hover { background: #f0f0f0; }
    
    .conf-bar-bg { width: 100px; height: 6px; background: #ddd; display: inline-block; vertical-align: middle; margin-left: 10px; border-radius: 3px; overflow: hidden; }
    .conf-bar-fill { height: 100%; background: #1a1a1a; }
    
    .pass-table { width: 100%; border-collapse: collapse; margin-top: 50px; font-size: 12px; color: #666; }
    .pass-table th { text-align: left; border-bottom: 2px solid var(--border); padding: 8px; background: #f9f9f9; }
    .pass-table td { border-bottom: 1px solid #f0f0f0; padding: 8px; }
    
    .footer { margin-top: 100px; padding: 20px 0; border-top: 1px solid var(--border); font-family: monospace; font-size: 11px; color: #888; text-align: center; }
    """
    
    script = """
    function copyCmd(btn) {
        var code = btn.nextSibling.textContent;
        navigator.clipboard.writeText(code).then(() => {
            var oldText = btn.innerText;
            btn.innerText = "copied";
            setTimeout(() => { btn.innerText = oldText; }, 1500);
        });
    }
    """

    findings_html = ""
    for sev in severity_order:
        items = grouped_results[sev]
        if not items: continue
        
        findings_html += f"<div class='finding-group-title'>{sev} FINDINGS</div>"
        
        for r in items:
            sev_lvl = r["severity"].lower()
            conf = r.get("confidence", 0)
            what = html_module.escape(r.get("what_found", ""))
            module = html_module.escape(r["module"])
            check = html_module.escape(r["check"])
            
            # Exposure Detail
            exp = r.get("exposure_detail", {})
            leaked = exp.get("leaked_data", [])
            intel = html_module.escape(exp.get("extra_intel", ""))
            surface = html_module.escape(exp.get("attack_surface", ""))
            
            leaked_items = "".join([f"<li>{html_module.escape(str(l))}</li>" for l in leaked])
            leaked_html = f"<div>Leaked data:<ul>{leaked_items}</ul></div>" if leaked else ""
            
            # Manual Test
            manual = r.get("manual_test", [])
            manual_steps = ""
            for s in manual:
                manual_steps += f"""
                <div style="margin-bottom:15px;">
                    <div style="font-weight:600; font-size:12px;">Step {s['step']} — {html_module.escape(s['action'])}</div>
                    <code-block><button class="copy-btn" onclick="copyCmd(this)">copy</button><span>{html_module.escape(s['command'])}</span></code-block>
                    <div style="font-size:12px; color:#666;">Expected: {html_module.escape(s['expected'])}</div>
                </div>
                """

            findings_html += f"""
            <div class="card {sev_lvl}">
                <div class="card-header">
                    <div class="title">[{sev}] {module} — {check}</div>
                    <div class="conf">conf: {conf}% <div class="conf-bar-bg"><div class="conf-bar-fill" style="width:{conf}%"></div></div></div>
                </div>
                <div class="card-body">
                    <div class="section-title">What was found</div>
                    <div class="section-content">{what}</div>
                    
                    <div class="section-title">Exposure detail</div>
                    <div class="section-content">
                        {leaked_html}
                        {f'<div>Intel: {intel}</div>' if intel else ''}
                        {f'<div>Attack scope: {surface}</div>' if surface else ''}
                    </div>
                    
                    {f'<div class="section-title">Manual verification</div><div class="section-content">{manual_steps}</div>' if manual_steps else ''}
                </div>
            </div>
            """

    pass_rows = ""
    for r in passed_results:
        pass_rows += f"<tr><td>{html_module.escape(r['module'])}</td><td>{html_module.escape(r['check'])}</td><td>[PASS]</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>{styles}</style>
<script>{script}</script>
<title>Assessment Report — {html_module.escape(target)}</title>
</head>
<body>
<div class="header-bar">WebSec Scanner — v2.5 (Security Audit Engine)</div>
<div class="container">
    <div class="meta-box">
        <div class="score-display">SCORE: {score} / 100</div>
        <div class="rating">Rating: {rating}</div>
        
        <div style="margin-top:20px; color:#666;">
            Target: {html_module.escape(target)}<br>
            Date: {now}<br>
            Duration: {duration:.1f}s
        </div>

        <table class="summary-table">
            <tr><td>CRITICAL</td><td>{counts['CRITICAL']} finding(s)</td></tr>
            <tr><td>HIGH</td><td>{counts['HIGH']} finding(s)</td></tr>
            <tr><td>MEDIUM</td><td>{counts['MEDIUM']} finding(s)</td></tr>
            <tr><td>LOW</td><td>{counts['LOW']} finding(s)</td></tr>
            <tr><td>PASS</td><td>{passed_count} check(s) passed</td></tr>
        </table>
    </div>

    {findings_html}

    <details style="margin-top:80px;">
        <summary style="cursor:pointer; font-weight:600; color:#888;">VIEW PASSED CHECKS ({passed_count})</summary>
        <table class="pass-table">
            <thead>
                <tr><th>Module</th><th>Check</th><th>Result</th></tr>
            </thead>
            <tbody>
                {pass_rows}
            </tbody>
        </table>
    </details>

    <div class="footer">
        CONFIDENTIAL SECURITY ASSESSMENT REPORT<br>
        Generated by WebSec Scanner. Educational purposes only.
    </div>
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
    In tóm tắt kết quả ra terminal (Professional Audit Format).
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    passed = sum(1 for r in results if r["status"] == "PASS")
    crit = sum(1 for r in results if r["severity"] == "CRITICAL" and r["status"] == "FAIL")
    high = sum(1 for r in results if r["severity"] == "HIGH" and r["status"] == "FAIL")
    med = sum(1 for r in results if r["severity"] == "MEDIUM" and r["status"] == "FAIL")
    low = sum(1 for r in results if r["severity"] == "LOW" and r["status"] == "FAIL")
    
    label = get_score_label(score)

    print("\n  ================================================================")
    print("  WebSec Scanner — Security Assessment Report")
    print(f"  Target  : {target}")
    print(f"  Started : {now}")
    print(f"  Duration: {duration:.1f}s")
    print("  ================================================================")
    print(f"\n  SCORE: {score} / 100  [{label}]")
    print("\n  FINDINGS SUMMARY")
    print("  ----------------")
    print(f"  CRITICAL    {crit}")
    print(f"  HIGH        {high}")
    print(f"  MEDIUM      {med}")
    print(f"  LOW         {low}")
    print(f"  PASS       {passed}")

    # Hiển thị CRITICAL / HIGH findings
    high_issues = [r for r in results if r["status"] == "FAIL" and r["severity"] in ("CRITICAL", "HIGH")]
    if high_issues:
        print("\n  CRITICAL / HIGH FINDINGS")
        print("  ------------------------")
        for r in high_issues:
            sev = r["severity"]
            conf = r.get("confidence", 0)
            msg = r.get("what_found", r.get("description", ""))
            line = f"  [{sev:8}]  {r['module']:15}  {msg[:50]} (confidence: {conf}%)"
            
            if HAS_COLORAMA:
                print(f"{Fore.RED}{line}{Style.RESET_ALL}")
            else:
                print(line)

    print("\n  ================================================================")
