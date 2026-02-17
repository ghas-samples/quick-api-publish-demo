"""
Core application class for QuickAPI framework.
"""

import json
from typing import Callable, Dict, Any, Optional


class QuickAPI:
    """Main application class that handles routing and request dispatching."""

    def __init__(self, app_name: str, debug: bool = False):
        self.app_name = app_name
        self.debug = debug
        self._routes: Dict[str, Dict[str, Callable]] = {}
        self._middleware: list = []
        self._config: Dict[str, Any] = {}

    def route(self, path: str, methods: list = None):
        """Decorator to register a route handler."""
        if methods is None:
            methods = ["GET"]

        def decorator(func: Callable):
            for method in methods:
                key = f"{method.upper()}:{path}"
                self._routes[key] = {"handler": func, "path": path, "method": method}
            return func

        return decorator

    def add_middleware(self, middleware_func: Callable):
        """Add middleware to the request processing pipeline."""
        self._middleware.append(middleware_func)

    def configure(self, config: Dict[str, Any]):
        """Load application configuration."""
        self._config.update(config)

    def get_config(self, key: str, default: Any = None) -> Any:
        """Retrieve a configuration value."""
        return self._config.get(key, default)

    def dispatch(self, method: str, path: str, request) -> Any:
        """Dispatch a request to the appropriate handler."""
        key = f"{method.upper()}:{path}"
        route = self._routes.get(key)
        if route:
            return route["handler"](request)
        return None

    def run(self, host: str = "0.0.0.0", port: int = 8080):
        """Start the application server (simulated)."""
        print(f"[{self.app_name}] Starting on {host}:{port} (debug={self.debug})")
