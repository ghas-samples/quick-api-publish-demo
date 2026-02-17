"""
Response classes for QuickAPI framework.
"""

import json
from typing import Any, Dict, Optional


class Response:
    """Base HTTP response."""

    def __init__(self, body: str = "", status_code: int = 200, content_type: str = "text/plain"):
        self.body = body
        self.status_code = status_code
        self.content_type = content_type
        self._headers: Dict[str, str] = {"Content-Type": content_type}

    def set_header(self, name: str, value: str):
        """Set a response header."""
        self._headers[name] = value

    def set_cookie(self, name: str, value: str, **kwargs):
        """Set a cookie on the response."""
        cookie_str = f"{name}={value}"
        self._headers["Set-Cookie"] = cookie_str

    def redirect(self, url: str, permanent: bool = False):
        """Redirect to another URL (potential open-redirect SINK)."""
        self.status_code = 301 if permanent else 302
        self._headers["Location"] = url


class JSONResponse(Response):
    """JSON HTTP response."""

    def __init__(self, data: Any, status_code: int = 200):
        body = json.dumps(data)
        super().__init__(body=body, status_code=status_code, content_type="application/json")
        self.data = data


class HTMLResponse(Response):
    """HTML HTTP response — body is rendered directly into the page (SINK for XSS)."""

    def __init__(self, html_content: str, status_code: int = 200):
        super().__init__(body=html_content, status_code=status_code, content_type="text/html")
