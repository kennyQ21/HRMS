from abc import ABC, abstractmethod
from typing import Dict, Any, List
from constants import PII_TYPES

class BaseParser(ABC):
    """Base class for all file parsers"""
    
    def __init__(self):
        self.pii_types = PII_TYPES
    
    @abstractmethod
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse the file and return structured data"""
        pass
    
    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the parsed data"""
        pass
    
    def extract_pii(self, data: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """Extract PII from parsed data using existing PII patterns"""
        findings = []
        