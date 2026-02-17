"""
Data transformation utilities for QuickAPI framework.

These are SUMMARIES — they transform data while preserving taint.
The CodeQL model editor should model these so taint flows through them.
"""

import json
import copy
from typing import Any, Dict, List, Optional


class DataTransformer:
    """
    Utility class for transforming data between formats.

    All methods here propagate taint: the output is derived from the input.
    """

    @staticmethod
    def to_json(data: Any) -> str:
        """Convert data to a JSON string (SUMMARY: value flows through)."""
        return json.dumps(data)

    @staticmethod
    def from_json(json_str: str) -> Any:
        """Parse a JSON string into Python objects (SUMMARY: taint flows through)."""
        return json.loads(json_str)

    @staticmethod
    def merge_dicts(base: Dict, override: Dict) -> Dict:
        """
        Merge two dicts, with `override` taking precedence.

        SUMMARY: taint from either input flows to the output.
        """
        result = copy.deepcopy(base)
        result.update(override)
        return result

    @staticmethod
    def extract_field(data: Dict[str, Any], field: str) -> Any:
        """
        Extract a single field from a dict.

        SUMMARY: taint flows from data[field] to the return value.
        """
        return data.get(field)

    @staticmethod
    def wrap_in_list(item: Any) -> List[Any]:
        """Wrap a single item in a list (SUMMARY: value preserved)."""
        return [item]

    @staticmethod
    def join_strings(parts: List[str], separator: str = "") -> str:
        """Join a list of strings (SUMMARY: taint flows through)."""
        return separator.join(parts)

    @staticmethod
    def format_string(template: str, **kwargs) -> str:
        """
        Format a string template with keyword arguments.

        SUMMARY: taint from kwargs flows to the return value.
        """
        return template.format(**kwargs)


class CacheManager:
    """
    In-memory cache manager.

    Taint flows through the cache: data stored via `set` flows out via `get`.
    """

    def __init__(self):
        self._store: Dict[str, Any] = {}

    def set(self, key: str, value: Any, ttl: int = 300):
        """Store a value in the cache (SUMMARY: taint flows in)."""
        self._store[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value from the cache (SUMMARY: taint flows out)."""
        return self._store.get(key, default)

    def get_or_compute(self, key: str, compute_func) -> Any:
        """Get from cache or compute and store the result."""
        if key not in self._store:
            self._store[key] = compute_func()
        return self._store[key]
