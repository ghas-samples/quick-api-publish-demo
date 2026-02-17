"""
Request handling for QuickAPI framework.

These classes represent SOURCES of user-controlled data. When modeling this
framework, the methods that return user input should be modeled as taint sources.
"""

from typing import Any, Dict, Optional
import json


class Request:
    """
    Represents an incoming HTTP request.

    In a real framework this wraps the WSGI/ASGI environment.
    All data returned by this class's methods comes from the end user
    and should be considered UNTRUSTED.
    """

    def __init__(self, environ: Optional[Dict[str, Any]] = None):
        self._environ = environ or {}
        self._headers = self._environ.get("headers", {})
        self._query_params = self._environ.get("query_params", {})
        self._body = self._environ.get("body", "")
        self._form_data = self._environ.get("form_data", {})
        self._cookies = self._environ.get("cookies", {})
        self._files = self._environ.get("files", {})

    # ── Sources of user-controlled data ─────────────────────────────

    def get_query_param(self, name: str, default: str = "") -> str:
        """Return a single query-string parameter value (SOURCE)."""
        return self._query_params.get(name, default)

    def get_all_query_params(self) -> Dict[str, str]:
        """Return all query-string parameters (SOURCE)."""
        return dict(self._query_params)

    def get_header(self, name: str, default: str = "") -> str:
        """Return a single HTTP header value (SOURCE)."""
        return self._headers.get(name.lower(), default)

    def get_json_body(self) -> Any:
        """Parse and return the JSON request body (SOURCE)."""
        if isinstance(self._body, str):
            return json.loads(self._body) if self._body else {}
        return self._body

    def get_raw_body(self) -> str:
        """Return the raw request body as a string (SOURCE)."""
        return self._body

    def get_form_field(self, name: str, default: str = "") -> str:
        """Return a form field value (SOURCE)."""
        return self._form_data.get(name, default)

    def get_cookie(self, name: str, default: str = "") -> str:
        """Return a cookie value (SOURCE)."""
        return self._cookies.get(name, default)

    def get_uploaded_filename(self, field_name: str) -> str:
        """Return the filename of an uploaded file (SOURCE)."""
        file_info = self._files.get(field_name, {})
        return file_info.get("filename", "")

    @property
    def path(self) -> str:
        """The request path (SOURCE)."""
        return self._environ.get("path", "/")

    @property
    def method(self) -> str:
        """The HTTP method."""
        return self._environ.get("method", "GET")

    @property
    def remote_addr(self) -> str:
        """The client's IP address."""
        return self._environ.get("remote_addr", "127.0.0.1")
