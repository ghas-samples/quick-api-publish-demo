"""
Security utilities for QuickAPI framework.

Contains both sinks (things that consume sensitive operations) and
summaries (things that transform data while preserving taint).
"""

import hashlib
import hmac
import subprocess
from typing import Optional


class TokenValidator:
    """Validates and decodes authentication tokens."""

    def __init__(self, secret_key: str):
        self._secret_key = secret_key

    def decode_token(self, token: str) -> dict:
        """
        Decode and validate a token, returning its claims.

        The returned dict contains user-controlled data from the token —
        this is a SOURCE of taint (remote user data embedded in the token).
        """
        # Simplified token "decoding" for demo purposes
        import base64
        import json

        try:
            parts = token.split(".")
            payload = base64.b64decode(parts[1] + "==")
            return json.loads(payload)
        except (IndexError, Exception):
            return {}

    def get_user_id(self, token: str) -> Optional[str]:
        """Extract user ID from token (SOURCE — user-controlled)."""
        claims = self.decode_token(token)
        return claims.get("sub")


class Sanitizer:
    """
    Input sanitization utilities.

    These methods transform data — they are SUMMARIES because taint flows
    through them (the output is derived from the input but may be partially
    cleaned).
    """

    @staticmethod
    def strip_tags(html: str) -> str:
        """
        Remove HTML tags from a string (SUMMARY: taint flows through).

        NOTE: This is a naive implementation and does NOT fully prevent XSS.
        """
        import re

        return re.sub(r"<[^>]*>", "", html)

    @staticmethod
    def truncate(value: str, max_length: int = 255) -> str:
        """Truncate a string to max_length (SUMMARY: taint flows through)."""
        return value[:max_length]

    @staticmethod
    def to_lowercase(value: str) -> str:
        """Convert to lowercase (SUMMARY: taint flows through)."""
        return value.lower()


class SystemHelper:
    """
    System-level utilities.

    Contains command-injection SINKS.
    """

    @staticmethod
    def run_command(cmd: str) -> str:
        """
        Execute a system command and return its output.

        `cmd` is a SINK for command-injection.
        """
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout

    @staticmethod
    def ping_host(hostname: str) -> str:
        """
        Ping a host and return the result.

        `hostname` is a SINK for command-injection.
        """
        result = subprocess.run(
            f"ping -c 1 {hostname}", shell=True, capture_output=True, text=True
        )
        return result.stdout

    @staticmethod
    def read_file(filepath: str) -> str:
        """
        Read and return the contents of a file.

        `filepath` is a SINK for path-injection.
        """
        with open(filepath, "r") as f:
            return f.read()

    @staticmethod
    def write_log(logfile: str, message: str):
        """
        Write a message to a log file.

        `message` is a SINK for log-injection.
        """
        with open(logfile, "a") as f:
            f.write(message + "\n")
