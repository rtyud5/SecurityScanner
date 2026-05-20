"""
Hàm tiện ích dùng chung cho WebSec Scanner.
Bao gồm: xử lý URL, gửi HTTP request an toàn, phát hiện soft 404,
load wordlist, tính điểm, nhãn đánh giá.
"""

import os
import re
import logging
import requests
from urllib.parse import urlparse

from source.config import (
    DEFAULT_TIMEOUT, USER_AGENT, SOFT_404_SIGNATURES, SENSITIVE_PATHS
)

# Logger cho toàn bộ project
logger = logging.getLogger("websec-scanner")


def get_base_url(url):
    """Lấy phần gốc của URL: https://example.com (không có path)"""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_url(url):
    """Đảm bảo URL có scheme. Nếu thiếu thì thêm https://"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def validate_url(url):
    """Kiểm tra URL có hợp lệ không"""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return False
    # Kiểm tra domain có ít nhất 1 dấu chấm hoặc là localhost
    if "." not in parsed.netloc and "localhost" not in parsed.netloc:
        return False
    return True


def safe_get(url, verify_ssl=False, **kwargs):
    """
    Gửi GET request an toàn, trả về None nếu có lỗi (thay vì crash).
    Phân loại exception cụ thể để dễ debug hơn.
    """
    headers = kwargs.pop("headers", {})
    if "User-Agent" not in headers:
        headers["User-Agent"] = USER_AGENT
    try:
        return requests.get(url, timeout=DEFAULT_TIMEOUT, verify=verify_ssl,
                            headers=headers, **kwargs)
    except requests.exceptions.Timeout:
        logger.debug(f"Timeout khi kết nối {url}")
        return None
    except requests.exceptions.SSLError as e:
        logger.debug(f"SSL error {url}: {e}")
        return None
    except requests.exceptions.ConnectionError:
        logger.debug(f"Không thể kết nối {url}")
        return None
    except requests.exceptions.RequestException as e:
        logger.warning(f"Request lỗi {url}: {type(e).__name__}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Lỗi không mong đợi khi request {url}: {type(e).__name__}: {e}")
        return None


def is_soft_404(response):
    """Kiểm tra xem response có phải là trang 404 giả không"""
    if response.status_code != 200:
        return False
    content = response.text.lower()[:2000]  # Chỉ check 2000 ký tự đầu
    title_match = re.search(r"<title>(.*?)</title>", content)
    if title_match:
        title = title_match.group(1).lower()
        for sig in SOFT_404_SIGNATURES:
            if sig in title:
                return True
    # Check body nếu response ngắn (< 1KB thường là error page)
    if len(response.text) < 1024:
        for sig in SOFT_404_SIGNATURES:
            if sig in content:
                return True
    return False


def load_wordlist_paths(wordlist_file=None):
    """
    Load danh sách path từ wordlist file. Trả về None nếu không có file.
    Có guard cho lỗi encoding và lỗi đọc file.
    """
    if wordlist_file is None:
        # Tìm file mặc định: từ thư mục gốc project / wordlists/
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wordlist_file = os.path.join(project_root, "wordlists", "sensitive_paths.txt")

    if not os.path.exists(wordlist_file):
        logger.info(f"Wordlist không tìm thấy: {wordlist_file}, dùng danh sách mặc định")
        return None  # Caller sẽ dùng SENSITIVE_PATHS

    try:
        paths = []
        with open(wordlist_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    paths.append(line)
        logger.info(f"Đã load {len(paths)} paths từ {wordlist_file}")
        return paths
    except UnicodeDecodeError:
        logger.warning(f"Wordlist encoding lỗi: {wordlist_file}, dùng danh sách mặc định")
        return None
    except OSError as e:
        logger.warning(f"Không đọc được wordlist {wordlist_file}: {e}")
        return None


def make_result(module, check_name, status, severity, description, fix=""):
    """
    Tạo dict kết quả chuẩn cho một lần kiểm tra.

    Args:
        module: Tên module thực hiện (vd: "Headers", "HTTPS")
        check_name: Tên kiểm tra cụ thể (vd: "X-Frame-Options")
        status: PASS / FAIL / WARN / INFO
        severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
        description: Mô tả chi tiết vấn đề
        fix: Khuyến nghị cách sửa (tùy chọn)
    """
    return {
        "module": module,
        "check": check_name,
        "status": status,
        "severity": severity,
        "description": description,
        "fix": fix
    }


def get_score_label(score):
    """
    Trả về nhãn đánh giá dựa trên điểm bảo mật.
    Hàm dùng chung cho engine.py và report/generator.py — tránh duplicate.
    """
    if score >= 80:
        return "TỐT 🟢"
    if score >= 60:
        return "TRUNG BÌNH 🟡"
    if score >= 40:
        return "KÉM 🟠"
    return "NGUY HIỂM 🔴"
