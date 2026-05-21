"""
Module 4: Kiểm tra Đường dẫn Nhạy cảm (Sensitive Path Discovery)
Quét song song các đường dẫn phổ biến có thể bị lộ, với soft 404 detection.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from source.config import SENSITIVE_PATHS, MAX_PATH_WORKERS
from source.utils import (
    make_result, safe_get, get_base_url, is_soft_404,
    load_wordlist_paths, logger
)


def _extract_intel(path, content, response):
    """
    Trích xuất intelligence từ nội dung file phát hiện được.
    """
    intel = {
        "leaked_data": [],
        "extra_intel": "",
        "attack_surface": "",
        "confidence": 50,
        "confidence_reason": "Dựa trên HTTP status code"
    }

    # Intel cho /.env
    if path == "/.env":
        # Tìm tên key nhạy cảm (không lấy value)
        pattern = r'^([A-Z_]{3,})\s*='
        keys = re.findall(pattern, content, re.MULTILINE)
        sensitive_keywords = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'API', 'DB_', 'CREDENTIALS']
        sensitive = [k for k in keys if any(word in k.upper() for word in sensitive_keywords)]
        
        intel["leaked_data"] = [f"{k}=[REDACTED]" for k in sensitive[:10]]
        intel["extra_intel"] = f"Phát hiện {len(keys)} biến môi trường, {len(sensitive)} biến nhạy cảm."
        
        if sensitive:
            intel["confidence"] = 90
            intel["confidence_reason"] = f"Tìm thấy {len(sensitive)} key pattern nhạy cảm trong nội dung"
        elif "=" in content:
            intel["confidence"] = 60
            intel["confidence_reason"] = "Nội dung có dạng KEY=VALUE nhưng không chứa key cực kỳ nhạy cảm"
        elif "<html" in content.lower():
            intel["confidence"] = 30
            intel["confidence_reason"] = "HTTP 200 nhưng nội dung có vẻ là trang HTML (có thể là trang lỗi giả)"

    # Intel cho /.git/config
    elif path == "/.git/config":
        url_match = re.search(r'url\s*=\s*(.+)', content)
        repo_url = url_match.group(1).strip() if url_match else "không xác định"
        intel["leaked_data"] = [f"Repository URL: {repo_url}"]
        if "[core]" in content or "[remote" in content:
            intel["confidence"] = 95
            intel["confidence_reason"] = "Phát hiện section chuẩn của git config ([core] hoặc [remote])"
        else:
            intel["confidence"] = 50

    # Intel cho /info.php hoặc /phpinfo.php
    elif "info.php" in path:
        php_ver = re.search(r'PHP Version\s*</td><td[^>]*>([0-9.]+)', content)
        os_match = re.search(r'System\s*</td><td[^>]*>([^<]+)', content)
        version = php_ver.group(1) if php_ver else "unknown"
        os_info = os_match.group(1)[:50].strip() if os_match else "unknown"
        intel["leaked_data"] = [f"PHP Version: {version}", f"OS: {os_info}"]
        if "phpinfo()" in content or "PHP Version" in content:
            intel["confidence"] = 92
            intel["confidence_reason"] = "Xác nhận cấu trúc HTML đặc trưng của phpinfo()"

    # Intel cho WordPress
    elif "wp-" in path:
        ver_match = re.search(r'ver=([0-9.]+)', content)
        if ver_match:
            intel["extra_intel"] = f"Phát hiện dấu hiệu WordPress version {ver_match.group(1)}"
            intel["confidence"] = 80
        else:
            intel["confidence"] = 70

    return intel


def _check_single_path(base, item, verify_ssl=True):
    """
    Kiểm tra một đường dẫn cụ thể và thực hiện phân tích sâu.
    """
    path = item["path"]
    severity = item["severity"]
    desc = item.get("desc", "Đường dẫn nhạy cảm")
    attack_tmpl = item.get("attack", "Attacker có thể lợi dụng thông tin này để leo thang tấn công.")
    manual_tmpl = item.get("manual_test", [])

    full_url = base + path
    r = safe_get(full_url, verify_ssl=verify_ssl)

    if r is None:
        return None

    if r.status_code == 200:
        if is_soft_404(r):
            return None

        # Phân tích sâu nội dung (tối đa 3000 chars)
        content = r.text[:3000]
        intel = _extract_intel(path, content, r)
        
        # Build manual tests với URL thực tế
        manual_test = []
        for step in manual_tmpl:
            manual_test.append({
                "step": step["step"],
                "action": step["action"],
                "command": step["command"].format(url=base),
                "expected": step["expected"]
            })

        return make_result(
            module="Path Scanner",
            check_name=f"Exposed: {path}",
            status="FAIL",
            severity=severity,
            what_found=f"Phát hiện đường dẫn {path} trả về trạng thái HTTP 200 (OK). {desc}",
            exposure_detail={
                "leaked_data": intel["leaked_data"],
                "extra_intel": intel["extra_intel"],
                "attack_surface": attack_tmpl
            },
            confidence=intel["confidence"],
            confidence_reason=intel["confidence_reason"],
            manual_test=manual_test
        )
    
    elif r.status_code == 403:
        return make_result(
            module="Path Scanner",
            check_name=f"Blocked: {path}",
            status="WARN",
            severity="LOW",
            what_found=f"Đường dẫn {path} tồn tại nhưng bị chặn (HTTP 403 Forbidden).",
            confidence=40,
            confidence_reason="Server từ chối truy cập nhưng đường dẫn có tồn tại trên filesystem",
            exposure_detail={
                "leaked_data": [],
                "extra_intel": "Truy cập bị chặn bởi server configuration hoặc WAF.",
                "attack_surface": "Hạn chế khả năng thu thập thông tin trực tiếp, nhưng vẫn xác nhận được sự tồn tại của file/dir."
            }
        )
    return None


def check_sensitive_paths(url, verify_ssl=True):
    """
    Thử các đường dẫn phổ biến có thể bị lệ.
    """
    results = []
    base = get_base_url(url)
    wordlist_paths = load_wordlist_paths()

    if wordlist_paths:
        path_items = []
        for p in wordlist_paths:
            matched = next((s for s in SENSITIVE_PATHS if s["path"] == p), None)
            if matched:
                path_items.append(matched)
            else:
                path_items.append({"path": p, "severity": "MEDIUM", "desc": "Đường dẫn nhạy cảm", "attack": "Lộ thông tin cấu trúc hoặc file nội bộ.", "manual_test": [{"step": 1, "action": "Kiểm tra trực tiếp", "command": f"curl -I {{url}}{p}", "expected": "HTTP 200"}]})
    else:
        path_items = SENSITIVE_PATHS

    with ThreadPoolExecutor(max_workers=MAX_PATH_WORKERS) as executor:
        futures = {
            executor.submit(_check_single_path, base, item, verify_ssl): item
            for item in path_items
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    logger.info(f"Path scanner: đã thử {len(path_items)} đường dẫn")
    print(f"      → Đã quét {len(path_items)} đường dẫn nhạy cảm")

    if not results:
        results.append(make_result(
            module="Path Scanner",
            check_name="Sensitive Paths",
            status="PASS",
            severity="INFO",
            what_found="Không tìm thấy đường dẫn nhạy cảm phổ biến.",
            confidence=100,
            confidence_reason="Đã kiểm tra toàn bộ danh sách wordlist và không có phản hồi 200/403 hợp lệ"
        ))

    return results
