from typing import Dict, Any, List
from ..base import BaseParser
import pandas as pd
import csv
import logging

logger = logging.getLogger(__name__)

class CSVParser(BaseParser):
    def __init__(self):
        super().__init__()
        self.pandas_available = self._check_pandas()
    
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse CSV file with automatic format detection"""
        try:
            if self.pandas_available:
                return self._parse_with_pandas(file_path)
            return self._parse_with_csv(file_path)
        except Exception as e:
            logger.error(f"CSV parsing failed: {str(e)}")
            raise
    
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the parsed CSV data"""
        if not data or 'data' not in data:
            return False
        
        required_metadata = ['columns', 'rows']
        return all(key in data['metadata'] for key in required_metadata)
    
    def _check_pandas(self) -> bool:
        try:
            import pandas
            return True
        except ImportError:
            return False
    
    def _parse_with_pandas(self, file_path: str) -> Dict[str, Any]:
        """Parse using pandas (preferred method)"""
        df = pd.read_csv(file_path)
        return {
            'data': df.to_dict('records'),
            'metadata': {
                'columns': df.columns.tolist(),
                'rows': len(df),
                'parser': 'pandas'
            }
        }
    
    def _parse_with_csv(self, file_path: str) -> Dict[str, Any]:
        """Fallback parser using csv module"""
        data = []
        headers = []
        
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            # Try to detect the dialect
            dialect = csv.Sniffer().sniff(csvfile.read(1024))
            csvfile.seek(0)
            
            reader = csv.reader(csvfile, dialect)
            headers = next(reader)  # Get headers
            
            for row in reader:
                row_data = {}
                for header, value in zip(headers, row):
                    row_data[header] = value
                data.append(row_data)
        
        return {
            'data': data,
            'metadata': {
                'columns': headers,
                'rows': len(data),
                'parser': 'csv'
            }
        }