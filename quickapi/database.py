"""
Database utilities for QuickAPI framework.

These classes contain SINKS — methods that execute SQL queries.
When modeling this framework, the query string parameters should be
modeled as SQL-injection sinks.
"""

import sqlite3
from typing import Any, Dict, List, Optional


class DatabaseConnection:
    """
    A simple database connection wrapper.

    Methods that accept raw SQL strings are potential SQL-injection sinks.
    """

    def __init__(self, connection_string: str):
        self._connection_string = connection_string
        self._connection: Optional[sqlite3.Connection] = None

    def connect(self):
        """Open the database connection."""
        self._connection = sqlite3.connect(self._connection_string)

    def close(self):
        """Close the database connection."""
        if self._connection:
            self._connection.close()

    # ── SQL-injection sinks ─────────────────────────────────────────

    def execute_query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """
        Execute a SQL query and return results as a list of dicts.

        `sql` is a SINK for sql-injection when constructed from user input.
        """
        if not self._connection:
            self.connect()
        cursor = self._connection.cursor()
        cursor.execute(sql, params)
        columns = [desc[0] for desc in cursor.description or []]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def execute_update(self, sql: str, params: tuple = ()) -> int:
        """
        Execute a SQL INSERT/UPDATE/DELETE and return affected row count.

        `sql` is a SINK for sql-injection when constructed from user input.
        """
        if not self._connection:
            self.connect()
        cursor = self._connection.cursor()
        cursor.execute(sql, params)
        self._connection.commit()
        return cursor.rowcount

    def execute_raw(self, sql: str) -> Any:
        """
        Execute raw SQL with no parameterization at all.

        `sql` is a SINK for sql-injection.
        """
        if not self._connection:
            self.connect()
        cursor = self._connection.cursor()
        cursor.executescript(sql)
        return cursor.fetchall()


class QueryBuilder:
    """
    A fluent query builder — the final built query still goes through
    DatabaseConnection, but the `.where_raw()` method directly interpolates
    user input, making it a sink.
    """

    def __init__(self, table: str):
        self._table = table
        self._conditions: List[str] = []
        self._columns = "*"
        self._order_by: Optional[str] = None
        self._limit: Optional[int] = None

    def select(self, *columns: str) -> "QueryBuilder":
        """Choose columns to select."""
        self._columns = ", ".join(columns) if columns else "*"
        return self

    def where_raw(self, condition: str) -> "QueryBuilder":
        """
        Add a raw WHERE clause — SINK for sql-injection.

        This is dangerous because it interpolates the condition directly.
        """
        self._conditions.append(condition)
        return self

    def order_by(self, column: str, direction: str = "ASC") -> "QueryBuilder":
        """Set ORDER BY clause."""
        self._order_by = f"{column} {direction}"
        return self

    def limit(self, count: int) -> "QueryBuilder":
        """Limit the number of results."""
        self._limit = count
        return self

    def build(self) -> str:
        """Build and return the SQL string (SUMMARY: taint flows from where_raw input to here)."""
        sql = f"SELECT {self._columns} FROM {self._table}"
        if self._conditions:
            sql += " WHERE " + " AND ".join(self._conditions)
        if self._order_by:
            sql += f" ORDER BY {self._order_by}"
        if self._limit is not None:
            sql += f" LIMIT {self._limit}"
        return sql
