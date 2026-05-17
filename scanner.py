"""
WebSec Scanner - Công cụ quét bảo mật website cơ bản
Dành cho mục đích học tập - chỉ dùng trên website bạn được phép kiểm tra

Sử dụng:
    python scanner.py --url https://example.com
    python scanner.py --url https://example.com --no-verify --verbose
"""

from source.engine import main

if __name__ == "__main__":
    main()
