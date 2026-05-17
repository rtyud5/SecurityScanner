"""
Module 6: Kiểm tra CORS Policy
Phát hiện cấu hình CORS quá rộng có thể cho phép website độc hại đọc dữ liệu.
"""

from source.utils import make_result, safe_get


def check_cors(url):
    """
    Kiểm tra cấu hình CORS bằng cách gửi request với Origin giả.
    Kiểm tra cả null origin (exploit qua sandboxed iframe).

    Args:
        url: URL cần kiểm tra

    Returns:
        list[dict]: Danh sách ScanResult
    """
    results = []
    fake_origin = "https://evil-attacker-site.com"

    r = safe_get(url, headers={"Origin": fake_origin})
    if r is None:
        return results

    acao = r.headers.get("Access-Control-Allow-Origin", "")

    # ── Test null origin (exploit qua sandboxed iframe) ──
    r_null = safe_get(url, headers={"Origin": "null"})
    if r_null:
        acao_null = r_null.headers.get("Access-Control-Allow-Origin", "")
        if acao_null == "null":
            results.append(make_result(
                module="CORS",
                check_name="CORS Null Origin",
                status="FAIL",
                severity="HIGH",
                description="CORS chấp nhận null origin — có thể bị exploit qua sandboxed iframe",
                fix="Không cho phép null origin trong CORS policy"
            ))

    # ── Test CORS policy chính ──
    acac = r.headers.get("Access-Control-Allow-Credentials", "false").lower()

    if acao == "*" and acac == "true":
        results.append(make_result(
            module="CORS",
            check_name="CORS Policy",
            status="FAIL",
            severity="HIGH",
            description="CORS nguy hiểm: Allow-Origin=* kết hợp Allow-Credentials=true",
            fix="Không được dùng wildcard (*) khi Allow-Credentials=true. Chỉ định domain cụ thể."
        ))
    elif acao == "*":
        results.append(make_result(
            module="CORS",
            check_name="CORS Policy",
            status="WARN",
            severity="LOW",
            description="CORS cho phép mọi origin (Access-Control-Allow-Origin: *)",
            fix="Chỉ chấp nhận nếu đây là public API. Nếu có dữ liệu nhạy cảm, hãy chỉ định domain."
        ))
    elif acao == fake_origin:
        results.append(make_result(
            module="CORS",
            check_name="CORS Policy",
            status="FAIL",
            severity="HIGH",
            description="CORS phản chiếu Origin tùy ý — mọi website đều được chấp nhận",
            fix="Chỉ cho phép các domain đã được whitelist, không phản chiếu Origin tự động"
        ))
    else:
        results.append(make_result(
            module="CORS",
            check_name="CORS Policy",
            status="PASS",
            severity="INFO",
            description=f"CORS được cấu hình hợp lý: '{acao}'" if acao else "Không có CORS header"
        ))

    return results
