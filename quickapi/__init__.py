"""
QuickAPI - A fictional Python web framework for CodeQL Model Editor demos.

This framework is intentionally NOT modeled by CodeQL, so it serves as an
example of an "unsupported framework" that you can model using the CodeQL
Model Editor in VS Code.
"""

from quickapi.app import QuickAPI
from quickapi.request import Request
from quickapi.response import Response, JSONResponse, HTMLResponse
from quickapi.database import DatabaseConnection, QueryBuilder
from quickapi.templating import TemplateEngine
from quickapi.security import TokenValidator, Sanitizer
from quickapi.utils import DataTransformer, CacheManager

__version__ = "0.9.0"
__all__ = [
    "QuickAPI",
    "Request",
    "Response",
    "JSONResponse",
    "HTMLResponse",
    "DatabaseConnection",
    "QueryBuilder",
    "TemplateEngine",
    "TokenValidator",
    "Sanitizer",
    "DataTransformer",
    "CacheManager",
]
