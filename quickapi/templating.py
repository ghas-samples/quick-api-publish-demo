"""
Templating engine for QuickAPI framework.

The `render` and `render_string` methods are SINKS for HTML/JS injection (XSS)
when user-controlled data is passed in without escaping.
"""

import os
from typing import Any, Dict


class TemplateEngine:
    """
    A minimal template engine that replaces {{variable}} placeholders.

    This engine does NOT auto-escape output, making it a potential XSS sink.
    """

    def __init__(self, template_dir: str = "templates"):
        self.template_dir = template_dir

    def render(self, template_name: str, context: Dict[str, Any] = None) -> str:
        """
        Render a template file with the given context.

        Values in `context` are interpolated WITHOUT escaping — this is a
        SINK for html-injection / js-injection if context values come from
        user input.
        """
        context = context or {}
        template_path = os.path.join(self.template_dir, template_name)
        with open(template_path, "r") as f:
            template_content = f.read()
        return self._interpolate(template_content, context)

    def render_string(self, template_str: str, context: Dict[str, Any] = None) -> str:
        """
        Render an inline template string with the given context.

        `template_str` is a SINK for html-injection if it contains user input.
        """
        context = context or {}
        return self._interpolate(template_str, context)

    def _interpolate(self, template: str, context: Dict[str, Any]) -> str:
        """Replace {{key}} placeholders with context values (no escaping)."""
        result = template
        for key, value in context.items():
            result = result.replace("{{" + key + "}}", str(value))
        return result
