from typing import Dict, Any, List
from ..base import BaseParser
import os
import re
from collections import defaultdict

class SQLParser(BaseParser):
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse SQL file and extract database structure and content"""
        text = self._read_sql_file(file_path)
        
        # Extract table definitions
        tables = self._extract_tables(text)
        
        # Extract procedures/functions
        procedures = self._extract_procedures(text)
        
        # Process the content for PII
        processed_text = self._preprocess_text_for_pii(text)
        
        # Add the full content as the final item
        data = [
            {
                'content_type': 'full_sql',
                'content': processed_text
            }
        ]
        
        # Add table definitions
        for table_name, table_def in tables.items():
            data.append({
                'content_type': 'table_definition',
                'table_name': table_name,
                'content': table_def,
                'columns': self._extract_columns(table_def)
            })
        
        # Add procedures
        for proc_name, proc_def in procedures.items():
            data.append({
                'content_type': 'procedure',
                'procedure_name': proc_name,
                'content': proc_def
            })
        
        return {
            'data': data,
            'metadata': {
                'columns': ['content_type', 'content'],
                'rows': len(data),
                'parser': 'sql',
                'tables': list(tables.keys()),
                'procedures': list(procedures.keys())
            }
        }
    
    def _read_sql_file(self, file_path: str) -> str:
        """Read SQL file content with various encodings support"""
        encodings = ['utf-8', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as file:
                    return file.read()
            except UnicodeDecodeError:
                continue
                
        # If all encodings fail, try binary mode and decode with errors ignored
        with open(file_path, 'rb') as file:
            return file.read().decode('utf-8', errors='ignore')
    
    def _extract_tables(self, text: str) -> Dict[str, str]:
        """Extract table definitions from SQL"""
        # Match CREATE TABLE statements
        create_pattern = re.compile(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\[\"\`]?(\w+)[\]\"\`]?\s*\((.*?);', 
                                   re.IGNORECASE | re.DOTALL | re.MULTILINE)
        
        tables = {}
        for match in create_pattern.finditer(text):
            table_name = match.group(1)
            table_def = match.group(0)
            tables[table_name] = table_def
            
        return tables
    
    def _extract_procedures(self, text: str) -> Dict[str, str]:
        """Extract stored procedures and functions from SQL"""
        # Match CREATE PROCEDURE or CREATE FUNCTION statements
        proc_pattern = re.compile(r'CREATE\s+(?:OR\s+REPLACE\s+)?(?:PROCEDURE|FUNCTION)\s+[\[\"\`]?(\w+)[\]\"\`]?(.*?END;|END\s*\$\$|END\s*//)', 
                                 re.IGNORECASE | re.DOTALL | re.MULTILINE)
        
        procedures = {}
        for match in proc_pattern.finditer(text):
            proc_name = match.group(1)
            proc_def = match.group(0)
            procedures[proc_name] = proc_def
            
        return procedures
    
    def _extract_columns(self, table_def: str) -> List[Dict[str, str]]:
        """Extract column definitions from table definition"""
        # Find the column definitions part between the first parentheses
        column_section_match = re.search(r'\((.*)\)', table_def, re.DOTALL)
        if not column_section_match:
            return []
            
        column_section = column_section_match.group(1)
        
        # Split by commas, but be careful with commas in default values or constraints
        lines = []
        current_line = ""
        paren_level = 0
        
        for char in column_section:
            if char == '(':
                paren_level += 1
            elif char == ')':
                paren_level -= 1
            
            if char == ',' and paren_level == 0:
                lines.append(current_line.strip())
                current_line = ""
            else:
                current_line += char
                
        if current_line:
            lines.append(current_line.strip())
        
        # Parse each column definition
        columns = []
        column_pattern = re.compile(r'[\[\"\`]?(\w+)[\]\"\`]?\s+([^,\(]+)')
        
        for line in lines:
            if 'PRIMARY KEY' in line.upper() or 'CONSTRAINT' in line.upper() or 'FOREIGN KEY' in line.upper():
                continue  # Skip constraints
                
            match = column_pattern.match(line)
            if match:
                column_name = match.group(1)
                data_type = match.group(2).strip()
                
                columns.append({
                    'name': column_name,
                    'type': data_type
                })
                
        return columns
    
    def _preprocess_text_for_pii(self, text: str) -> str:
        """Preprocess SQL text to normalize whitespace and format PII"""
        # Remove comments
        text = re.sub(r'--.*?$', '', text, flags=re.MULTILINE)
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        
        # Normalize whitespace
        text = re.sub(r'(?<!\n)\n(?!\n)', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        
        # Store original text for analysis
        original_text = text
        
        credit_card_pattern = re.compile(r'(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})')
        credit_cards = []
        
        # Find and format credit card numbers
        for match in credit_card_pattern.finditer(original_text):
            card_num = f"{match.group(1)} {match.group(2)} {match.group(3)} {match.group(4)}"
            credit_cards.append((match.start(), match.end(), card_num))
        
        # Now let's find phone numbers but avoid overlapping with credit cards
        phone_pattern = re.compile(r'(\d{3})[\s.-]*(\d{3})[\s.-]*(\d{4})')
        phones = []
        
        for match in phone_pattern.finditer(original_text):
            # Check if this match overlaps with any credit card
            overlaps = False
            for cc_start, cc_end, _ in credit_cards:
                if max(match.start(), cc_start) < min(match.end(), cc_end):
                    overlaps = True
                    break
            
            if not overlaps:
                phones.append((match.start(), match.end(), f"{match.group(1)}-{match.group(2)}-{match.group(3)}"))
        
        # Format dates without overlapping with other patterns
        date_pattern = re.compile(r'(\d{1,2})[\s.-/]+(\d{1,2})[\s.-/]+(\d{2,4})')
        dates = []
        
        for match in date_pattern.finditer(original_text):
            # Check for overlaps
            overlaps = False
            for start, end, _ in credit_cards + phones:
                if max(match.start(), start) < min(match.end(), end):
                    overlaps = True
                    break
            
            if not overlaps:
                dates.append((match.start(), match.end(), f"{match.group(1)}/{match.group(2)}/{match.group(3)}"))
        
        # Finally, look for ID numbers ONLY if they don't overlap with credit cards
        id_pattern = re.compile(r'(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})(?!\s*\d)')
        ids = []
        
        for match in id_pattern.finditer(original_text):
            # Check if this match is within a credit card number
            is_part_of_credit_card = False
            for cc_start, cc_end, _ in credit_cards:
                if match.start() >= cc_start and match.end() <= cc_end:
                    is_part_of_credit_card = True
                    break
            
            # Only add if it's not part of a credit card
            if not is_part_of_credit_card:
                ids.append((match.start(), match.end(), f"{match.group(1)} {match.group(2)} {match.group(3)}"))
        
        # Combine all matches in reverse order of position
        all_matches = sorted(credit_cards + phones + dates + ids, reverse=True)
        
        # Apply the replacements from end to beginning to avoid position shifts
        result = text
        for start, end, replacement in all_matches:
            # Calculate offsets if needed, this gets complex when replacing different length strings
            result = result[:start] + replacement + result[end:]
        
        return result
        
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the parsed SQL data"""
        if not data or 'data' not in data:
            return False
        
        if not data.get('data') or len(data['data']) == 0:
            return False
            
        required_metadata = ['columns', 'rows']
        return all(key in data.get('metadata', {}) for key in required_metadata)

