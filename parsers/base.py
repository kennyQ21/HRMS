import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from constants import PII_TYPES


class BaseParser(ABC):
    """Base class for all file parsers."""

    def __init__(self):
        self.pii_types = PII_TYPES

    @abstractmethod
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse the file and return structured data."""
        pass

    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the parsed data."""
        pass

    def extract_pii(self, data: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """
        Extract PII findings from parsed data without mutating the source.

        Returns:
            {'findings': [{'field': ..., 'pii_type': ..., 'value': ...,
                           'category': ..., 'sensitivity': ...}, ...]}
        """
        findings: List[Dict] = []

        if "data" not in data:
            return {"findings": findings}

        for row in data["data"]:
            if not isinstance(row, dict):
                continue
            for field, value in row.items():
                if value is None:
                    continue
                value_str = str(value)
                for pii_type in self.pii_types:
                    if "regex" not in pii_type:
                        continue
                    try:
                        pattern = re.compile(pii_type["regex"])
                        matches = pattern.findall(value_str)
                        for match in matches:
                            # findall can return strings or tuples (from groups)
                            matched_value = (
                                "".join(match) if isinstance(match, tuple) else match
                            )
                            findings.append(
                                {
                                    "field": field,
                                    "pii_type": pii_type["id"],
                                    "value": matched_value,
                                    "category": pii_type["category"].value,
                                    "sensitivity": pii_type["sensitivity"].value,
                                }
                            )
                    except Exception:
                        continue

        return {"findings": findings}