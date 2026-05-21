"""
Module 6: Kiểm tra CORS Policy
Phát hiện cấu hình CORS quá rộng có thể cho phép website độc hại đọc dữ liệu.
"""

from source.utils import make_result, safe_get


def check_cors(url, verify_ssl=True):
    """
    Kiểm tra cấu hình CORS chuyên sâu.
    """
    results = []
    fake_origin = "https://evil-attacker-site.com"

    r = safe_get(url, verify_ssl=verify_ssl, headers={"Origin": fake_origin})
    if r is None: return results

    acao = r.headers.get("Access-Control-Allow-Origin", "")

    # ── Test null origin ──
    r_null = safe_get(url, verify_ssl=verify_ssl, headers={"Origin": "null"})
    if r_null:
        acao_null = r_null.headers.get("Access-Control-Allow-Origin", "")
        if acao_null == "null":
            results.append(make_result(
                module="CORS",
                check_name="CORS Null Origin",
                status="FAIL",
                severity="HIGH",
                what_found="Máy chủ chấp nhận header 'Origin: null'.",
                confidence=95,
                confidence_reason="Server phản hồi Access-Control-Allow-Origin: null khi nhận request với Origin: null",
                exposure_detail={
                    "leaked_data": ["Access-Control-Allow-Origin: null"],
                    "extra_intel": "",
                    "attack_surface": "Attacker có thể sử dụng sandboxed iframe để vượt qua các hạn chế về domain và đọc dữ liệu nhạy cảm của người dùng từ website này."
                },
                manual_test=[
                    {"step": 1, "action": "Gửi request với null origin", "command": f"curl -H 'Origin: null' -I {url}", "expected": "Header 'Access-Control-Allow-Origin: null' xuất hiện trong kết quả"}
                ]
            ))

    # ── Test CORS policy chính ──
    acac = r.headers.get("Access-Control-Allow-Credentials", "false").lower()

    if acao == "*" and acac == "true":
        results.append(make_result(
            module="CORS",
            check_name="CORS Policy",
            status="FAIL",
            severity="HIGH",
            what_found="Kết hợp nguy hiểm giữa Wildcard (*) và Allow-Credentials.",
            confidence=98,
            exposure_detail={
                "leaked_data": ["Origin: *", "Credentials: true"],
                "extra_intel": "Cấu hình cực kỳ lỏng lẻo và không an toàn.",
                "attack_surface": "Cho phép bất kỳ website nào (bao gồm cả site độc hại) gửi request đi kèm với cookie/credentials của người dùng và đọc được dữ liệu phản hồi."
            },
            manual_test=[
                {"step": 1, "action": "Xác minh wildcard", "command": f"curl -H 'Origin: https://any-site.com' -I {url}", "expected": "Access-Control-Allow-Origin: *"},
                {"step": 2, "action": "Xác minh credentials", "command": f"curl -H 'Origin: https://any-site.com' -I {url}", "expected": "Access-Control-Allow-Credentials: true"}
            ]
        ))
    elif acao == "*":
        results.append(make_result(
            module="CORS",
            check_name="CORS Policy",
            status="WARN",
            severity="LOW",
            what_found="CORS cho phép mọi origin (Access-Control-Allow-Origin: *).",
            confidence=95,
            exposure_detail={
                "leaked_data": ["Origin: *"],
                "extra_intel": "Đang cho phép truy cập tài nguyên công khai từ mọi nguồn.",
                "attack_surface": "Nếu dữ liệu trên endpoint này không nhạy cảm thì rủi ro thấp. Nếu chứa thông tin định danh, attacker có thể đọc được nội dung từ site khác."
            }
        ))
    elif acao == fake_origin:
        results.append(make_result(
            module="CORS",
            check_name="CORS Policy",
            status="FAIL",
            severity="HIGH",
            what_found="CORS phản chiếu (reflect) Origin tự động mà không whitelist.",
            confidence=98,
            confidence_reason="Server trả về giá trị Origin đúng bằng giá trị Origin giả lập gửi lên",
            exposure_detail={
                "leaked_data": [f"Reflected: {fake_origin}"],
                "extra_intel": "",
                "attack_surface": "Đây là lỗ hổng nghiêm trọng tương đương với wildcard nhưng vượt qua được một số cơ chế bảo mật cũ. Mọi website đều có thể đọc dữ liệu từ endpoint này."
            },
            manual_test=[
                {"step": 1, "action": "Gửi Origin tùy ý", "command": f"curl -H 'Origin: https://malicious.com' -I {url}", "expected": "Access-Control-Allow-Origin: https://malicious.com"}
            ]
        ))
    else:
        results.append(make_result(
            module="CORS",
            check_name="CORS Policy",
            status="PASS",
            severity="INFO",
            what_found=f"CORS được cấu hình hợp lý hoặc không sử dụng: '{acao}'" if acao else "Không có CORS header",
            confidence=100
        ))

    return results
