from typing import Dict, Any, List
from ..base import BaseParser
import pandas as pd
import openpyxl
import logging

logger = logging.getLogger(__name__)

class ExcelParser(BaseParser):
    def __init__(self):
        super().__init__()
        self.pandas_available = self._check_pandas()
    
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse Excel file with automatic format detection"""
        try:
            if self.pandas_available:
                return self._parse_with_pandas(file_path)
            return self._parse_with_openpyxl(file_path)
        except Exception as e:
            logger.error(f"Excel parsing failed: {str(e)}")
            raise
    
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the parsed Excel data"""
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
        df = pd.read_excel(file_path)
        return {
            'data': df.to_dict('records'),
            'metadata': {
                'columns': df.columns.tolist(),
                'rows': len(df),
                'parser': 'pandas'
            }
        }
    
    def _parse_with_openpyxl(self, file_path: str) -> Dict[str, Any]:
        """Fallback parser using openpyxl"""
        wb = openpyxl.load_workbook(file_path, read_only=True)
        sheet = wb.active
        
        headers = [cell.value for cell in sheet[1]]
        data = []
        
        for row in sheet.iter_rows(min_row=2):
            row_data = {}
            for header, cell in zip(headers, row):
                row_data[header] = cell.value
            data.append(row_data)
            
        return {
            'data': data,
            'metadata': {
                'columns': headers,
                'rows': len(data),
                'parser': 'openpyxl'
            }
        }