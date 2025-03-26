from typing import Dict, Any, List
from ..base import BaseParser
import os

class MDBParser(BaseParser):
    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse an Access database (.mdb) file and extract table data."""
        import pyodbc
        
        all_data = []
        metadata = {
            'tables': [],
            'parser': 'mdb'
        }
        
        try:
            # Create connection to the MDB file
            conn_str = f"Driver={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={file_path};"
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            
            # Get list of tables
            tables = self._get_tables(cursor)
            metadata['tables'] = tables
            
            # Process each table
            for table_name in tables:
                table_data = self._process_table(cursor, table_name)
                all_data.append({
                    'table_name': table_name,
                    'columns': table_data['columns'],
                    'rows': table_data['rows']
                })
            
            conn.close()
            
        except Exception as e:
            print(f"Error parsing MDB file: {str(e)}")
            # Return minimal structure even on error
            return {
                'data': [],
                'metadata': {
                    'tables': [],
                    'columns': [],
                    'rows': 0,
                    'parser': 'mdb'
                }
            }
        
        return {
            'data': all_data,
            'metadata': metadata
        }
    
    def _get_tables(self, cursor) -> List[str]:
        """Extract table names from the MDB file."""
        tables = []
        
        try:
            # Different methods to get tables depending on pyodbc version
            try:
                # Try to get user tables (exclude system tables)
                for row in cursor.tables(tableType='TABLE'):
                    tables.append(row.table_name)
            except:
                # Alternative method
                cursor.execute("SELECT Name FROM MSysObjects WHERE Type=1 AND Flags=0")
                tables = [row[0] for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting tables: {str(e)}")
            
        return tables
    
    def _process_table(self, cursor, table_name: str) -> Dict[str, Any]:
        """Process a single table and extract its data."""
        result = {
            'columns': [],
            'rows': []
        }
        
        try:
            # Get column information
            cursor.execute(f"SELECT * FROM [{table_name}] WHERE 1=0")
            result['columns'] = [column[0] for column in cursor.description]
            
            # Get actual data
            cursor.execute(f"SELECT * FROM [{table_name}]")
            rows = cursor.fetchall()
            
            # Convert rows to list of dicts
            for row in rows:
                row_dict = {}
                for i, column in enumerate(result['columns']):
                    # Handle binary data and other special types
                    if isinstance(row[i], bytes):
                        row_dict[column] = "[BINARY DATA]"
                    else:
                        row_dict[column] = row[i]
                result['rows'].append(row_dict)
            
        except Exception as e:
            print(f"Error processing table {table_name}: {str(e)}")
        
        return result
    
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate the parsed MDB data."""
        if not data or 'data' not in data:
            return False
        
        if not data.get('metadata', {}).get('tables'):
            return False
            
        return True