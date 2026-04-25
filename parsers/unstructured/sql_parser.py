from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

import sqlparse
import sqlparse.sql as sqltypes
import sqlparse.tokens as T

import chardet

from ..base import BaseParser

logger = logging.getLogger(__name__)


class SQLParser(BaseParser):
    """
    Parses SQL files using the `sqlparse` library for structurally correct
    statement decomposition — regex cannot handle nested parentheses,
    semicolons inside string literals, or multi-dialect syntax reliably.
    """

    def parse(self, file_path: str) -> Dict[str, Any]:
        text = self._read_sql_file(file_path)

        # Strip SQL comments before structural analysis
        clean_text = self._strip_comments(text)

        tables = self._extract_tables(clean_text)
        procedures = self._extract_procedures(clean_text)

        data = [{"content_type": "full_sql", "content": clean_text}]

        for table_name, table_def in tables.items():
            data.append(
                {
                    "content_type": "table_definition",
                    "table_name": table_name,
                    "content": table_def,
                    "columns": self._extract_columns_from_def(table_def),
                }
            )

        for proc_name, proc_def in procedures.items():
            data.append(
                {
                    "content_type": "procedure",
                    "procedure_name": proc_name,
                    "content": proc_def,
                }
            )

        return {
            "data": data,
            "metadata": {
                "columns": ["content_type", "content"],
                "rows": len(data),
                "parser": "sql+sqlparse",
                "tables": list(tables.keys()),
                "procedures": list(procedures.keys()),
            },
        }

    def validate(self, data: Dict[str, Any]) -> bool:
        if not data or "data" not in data:
            return False
        if not data.get("data"):
            return False
        return all(k in data.get("metadata", {}) for k in ("columns", "rows"))

    # ── File reading ──────────────────────────────────────────────────────────

    def _read_sql_file(self, file_path: str) -> str:
        """Detect encoding with chardet before reading."""
        with open(file_path, "rb") as f:
            raw = f.read()

        detected = chardet.detect(raw)
        encoding = detected.get("encoding") or "utf-8"
        logger.debug("SQL file encoding detected: %s (confidence %.2f)", encoding, detected.get("confidence", 0))

        return raw.decode(encoding, errors="replace")

    # ── Comment stripping ─────────────────────────────────────────────────────

    def _strip_comments(self, text: str) -> str:
        """Remove SQL line and block comments using sqlparse token types."""
        stripped = []
        for stmt in sqlparse.parse(text):
            for token in stmt.flatten():
                if token.ttype in (T.Comment.Single, T.Comment.Multiline):
                    stripped.append(" ")
                else:
                    stripped.append(token.value)
        return "".join(stripped)

    # ── Table extraction ──────────────────────────────────────────────────────

    def _extract_tables(self, text: str) -> Dict[str, str]:
        """
        Extract CREATE TABLE statements using sqlparse.
        sqlparse correctly handles:
          - semicolons inside string literals / CHECK constraints
          - nested parentheses
          - IF NOT EXISTS qualifiers
          - quoted identifiers (backtick, double-quote, bracket)
        """
        tables: Dict[str, str] = {}

        for stmt in sqlparse.parse(text):
            if stmt.get_type() != "CREATE":
                continue

            tokens = [t for t in stmt.tokens if not t.is_whitespace]
            # Identify CREATE TABLE (or CREATE TEMP TABLE / CREATE TABLE IF NOT EXISTS)
            kw_values = [t.normalized.upper() for t in tokens if t.ttype in (T.Keyword, T.Keyword.DDL)]
            if "TABLE" not in kw_values:
                continue

            # Extract normalised table name
            table_name = self._get_identifier_name(tokens)
            if table_name:
                tables[table_name] = str(stmt).strip()

        return tables

    # ── Procedure extraction ──────────────────────────────────────────────────

    def _extract_procedures(self, text: str) -> Dict[str, str]:
        """
        Extract CREATE PROCEDURE / CREATE FUNCTION statements using sqlparse.
        Falls back to a single regex only as a safety net; sqlparse handles the
        main cases robustly.
        """
        procedures: Dict[str, str] = {}

        for stmt in sqlparse.parse(text):
            if stmt.get_type() != "CREATE":
                continue
            kw_values = [t.normalized.upper() for t in stmt.tokens if t.ttype in (T.Keyword, T.Keyword.DDL)]
            if not any(k in kw_values for k in ("PROCEDURE", "FUNCTION")):
                continue
            tokens = [t for t in stmt.tokens if not t.is_whitespace]
            proc_name = self._get_identifier_name(tokens)
            if proc_name:
                procedures[proc_name] = str(stmt).strip()

        return procedures

    # ── Column extraction ─────────────────────────────────────────────────────

    def _extract_columns_from_def(self, table_def: str) -> List[Dict[str, str]]:
        """
        Parse column definitions from a CREATE TABLE string.
        Uses sqlparse to locate the Parenthesis token (the column body),
        then splits intelligently respecting nested parentheses.
        """
        columns: List[Dict[str, str]] = []
        parsed = sqlparse.parse(table_def)
        if not parsed:
            return columns

        # Find the Parenthesis token that contains column definitions
        paren_token = None
        for token in parsed[0].tokens:
            if isinstance(token, sqltypes.Parenthesis):
                paren_token = token
                break

        if paren_token is None:
            return columns

        # Inner text without outer parentheses
        inner = str(paren_token)[1:-1]

        # Split on commas that are not inside nested parens
        parts = self._split_on_top_level_commas(inner)

        col_pattern = re.compile(r'[`"\[]?(\w+)[`"\]]?\s+(\S+.*)', re.DOTALL)

        for part in parts:
            part = part.strip()
            upper = part.upper()
            # Skip constraints / indexes
            if any(k in upper for k in ("PRIMARY KEY", "FOREIGN KEY", "CONSTRAINT", "INDEX", "UNIQUE", "CHECK")):
                continue
            m = col_pattern.match(part)
            if m:
                columns.append({"name": m.group(1), "type": m.group(2).split()[0]})

        return columns

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_identifier_name(tokens: list) -> str | None:
        """Return the first Identifier or plain Name token value (table/proc name)."""
        for token in tokens:
            if isinstance(token, sqltypes.Identifier):
                return token.get_name()
            if token.ttype is T.Name:
                return token.value
        return None

    @staticmethod
    def _split_on_top_level_commas(text: str) -> List[str]:
        """Split text on commas that sit at parenthesis depth 0."""
        parts: List[str] = []
        depth = 0
        current: List[str] = []

        for ch in text:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1

            if ch == "," and depth == 0:
                parts.append("".join(current))
                current = []
            else:
                current.append(ch)

        if current:
            parts.append("".join(current))

        return parts
