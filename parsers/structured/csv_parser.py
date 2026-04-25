import csv
import logging
from typing import Any, Dict, List

import chardet
import pandas as pd

from ..base import BaseParser

logger = logging.getLogger(__name__)


class CSVParser(BaseParser):
    def __init__(self):
        super().__init__()

    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse CSV file — auto-detects encoding then tries pandas, then stdlib csv."""
        try:
            encoding = self._detect_encoding(file_path)
            try:
                return self._parse_with_pandas(file_path, encoding)
            except Exception as e:
                logger.warning("pandas CSV parse failed (%s), falling back to csv stdlib", e)
                return self._parse_with_csv(file_path, encoding)
        except Exception as e:
            logger.error("CSV parsing failed: %s", e)
            raise

    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the parsed CSV data."""
        if not data or "data" not in data:
            return False
        required_metadata = ["columns", "rows"]
        return all(key in data["metadata"] for key in required_metadata)

    # ── Encoding detection ────────────────────────────────────────────────────

    def _detect_encoding(self, file_path: str) -> str:
        """
        Use chardet to sniff the file encoding from the first 64 KB.
        Falls back to utf-8 if detection is inconclusive.
        """
        with open(file_path, "rb") as f:
            raw = f.read(65536)
        result = chardet.detect(raw)
        encoding = result.get("encoding") or "utf-8"
        confidence = result.get("confidence", 0)
        logger.debug("Detected encoding=%s (confidence=%.2f) for %s", encoding, confidence, file_path)
        return encoding

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_with_pandas(self, file_path: str, encoding: str) -> Dict[str, Any]:
        """Parse using pandas — preferred for speed and type inference."""
        df = pd.read_csv(file_path, encoding=encoding, encoding_errors="replace")
        return {
            "data": df.to_dict("records"),
            "metadata": {
                "columns": df.columns.tolist(),
                "rows": len(df),
                "parser": "pandas",
                "encoding": encoding,
            },
        }

    def _parse_with_csv(self, file_path: str, encoding: str) -> Dict[str, Any]:
        """Fallback: stdlib csv reader."""
        data: List[Dict] = []
        headers: List[str] = []

        with open(file_path, "r", newline="", encoding=encoding, errors="replace") as csvfile:
            # Sniff dialect from a sample
            sample = csvfile.read(4096)
            csvfile.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample)
            except csv.Error:
                dialect = csv.excel  # type: ignore[assignment]

            reader = csv.reader(csvfile, dialect)
            headers = next(reader, [])

            for row in reader:
                data.append({h: v for h, v in zip(headers, row)})

        return {
            "data": data,
            "metadata": {
                "columns": headers,
                "rows": len(data),
                "parser": "csv",
                "encoding": encoding,
            },
        }