"""
WebSec Scanner — Entry point

Đây là điểm khởi chạy duy nhất của công cụ.
Logic chính nằm ở source/engine.py:
  - run_scan(url)  → chạy 7 module, trả về results (Flask gọi được)
  - main()         → parse CLI, gọi run_scan(), xuất report

Modules:  source/modules/   (header, info, https, path, cookie, cors, robots)
Config:   source/config.py  (hằng số, danh sách kiểm tra, scoring)
Utils:    source/utils.py   (normalize_url, safe_get, make_result, ...)
Report:   source/report/generator.py  (HTML, JSON, terminal output)

Sử dụng:
    python scanner.py --url https://example.com
    python scanner.py --url https://example.com --no-verify --verbose
"""

from source.engine import main

if __name__ == "__main__":
    main()
