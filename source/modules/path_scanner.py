"""
Module 4: Kiểm tra Đường dẫn Nhạy cảm (Sensitive Path Discovery)
Quét song song các đường dẫn phổ biến có thể bị lộ, với soft 404 detection.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from source.config import SENSITIVE_PATHS, MAX_PATH_WORKERS
from source.utils import (
    make_result, safe_get, get_base_url, is_soft_404,
    load_wordlist_paths, logger
)


def _check_single_path(base, path, severity="MEDIUM", desc="Đường dẫn nhạy cảm"):
    """
    Kiểm tra một đường dẫn cụ thể — dùng cho concurrent execution.

    Args:
        base: Base URL (vd: https://example.com)
        path: Đường dẫn cần kiểm tra (vd: /.env)
        severity: Mức độ nguy hiểm mặc định
        desc: Mô tả đường dẫn

    Returns:
        dict hoặc None: ScanResult nếu tìm thấy, None nếu không
    """
    full_url = base + path
    r = safe_get(full_url)

    if r is None:
        return None

    if r.status_code == 200:
        # Kiểm tra soft 404 để tránh false positive
        if is_soft_404(r):
            logger.debug(f"Soft 404 detected: {path}")
            return None
        return make_result(
            module="Path Scanner",
            check_name=f"Exposed: {path}",
            status="FAIL",
            severity=severity,
            description=f"Tìm thấy {path} (HTTP 200): {desc}",
            fix=f"Chặn truy cập vào {path} hoặc xóa file nếu không cần"
        )
    elif r.status_code == 403:
        return make_result(
            module="Path Scanner",
            check_name=f"Blocked: {path}",
            status="WARN",
            severity="LOW",
            description=f"Đường dẫn {path} tồn tại nhưng bị chặn (HTTP 403)",
            fix="Kiểm tra xem có cần đường dẫn này không, nếu không thì xóa"
        )
    return None


def check_sensitive_paths(url):
    """
    Thử các đường dẫn phổ biến có thể bị lộ.
    Dùng ThreadPoolExecutor để quét song song cho tốc độ tốt hơn.
    Load danh sách từ wordlists/sensitive_paths.txt nếu có.

    Args:
        url: URL cần quét

    Returns:
        list[dict]: Danh sách ScanResult
    """
    results = []
    base = get_base_url(url)

    # Thử load từ wordlist file, fallback về hardcoded list
    wordlist_paths = load_wordlist_paths()

    if wordlist_paths:
        # Tạo danh sách kiểm tra từ wordlist (severity mặc định MEDIUM)
        path_items = []
        for path in wordlist_paths:
            # Tìm severity từ SENSITIVE_PATHS nếu path trùng
            matched = next((s for s in SENSITIVE_PATHS if s["path"] == path), None)
            if matched:
                path_items.append(matched)
            else:
                path_items.append({"path": path, "severity": "MEDIUM", "desc": "Đường dẫn nhạy cảm"})
    else:
        path_items = SENSITIVE_PATHS

    # Quét song song với ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=MAX_PATH_WORKERS) as executor:
        futures = {
            executor.submit(_check_single_path, base, item["path"],
                            item["severity"], item["desc"]): item
            for item in path_items
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    if not results:
        results.append(make_result(
            module="Path Scanner",
            check_name="Sensitive Paths",
            status="PASS",
            severity="INFO",
            description="Không tìm thấy đường dẫn nhạy cảm phổ biến"
        ))

    return results
