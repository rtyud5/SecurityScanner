"""
Shared fixtures cho toàn bộ test suite.
Tập trung mock helpers ở đây — tránh copy-paste giữa các test file.
"""
import pytest
from unittest.mock import MagicMock

@pytest.fixture
def make_mock_response():
    """Factory fixture tạo mock HTTP response"""
    def _factory(headers=None, cookies=None, status_code=200, text=""):
        response = MagicMock()
        response.headers = headers or {}
        response.status_code = status_code
        response.text = text
        
        # Mock cookies — cần giống interface của requests.cookies
        if cookies is None:
            response.cookies = []
        else:
            response.cookies = cookies
        return response
    return _factory

@pytest.fixture
def make_mock_cookie():
    """Factory fixture tạo mock cookie với các flag bảo mật"""
    def _factory(name, secure=False, httponly=False, samesite=False):
        cookie = MagicMock()
        cookie.name = name
        cookie.secure = secure
        
        # has_nonstandard_attr() dùng để check HttpOnly và SameSite
        def _has_attr(attr_name):
            if attr_name.lower() == "httponly": return httponly
            if attr_name.lower() == "samesite": return samesite
            return False
        cookie.has_nonstandard_attr = MagicMock(side_effect=_has_attr)
        return cookie
    return _factory
