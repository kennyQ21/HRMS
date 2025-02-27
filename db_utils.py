from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import OperationalError
import re
from pymongo import MongoClient

def connect_to_db(db_type, db_name, user=None, password=None, host=None, port=None):
    try:
        if db_type.startswith("mongodb"):
            if db_type == "mongodb_standard":
                url = f"mongodb://{user}:{password}@{host}:{port}/{db_name}"
            elif db_type == "mongodb_srv":
                url = f"mongodb+srv://{user}:{password}@{host}/{db_name}"
            client = MongoClient(url)
            client.server_info()
            return client[db_name]
        
        # Build the connection URL for SQL databases
        elif db_type == "postgres":
            url = f"postgresql://{user}:{password}@{host}:{port}/{db_name}"
        elif db_type == "mysql":
            url = f"mysql+pymysql://{user}:{password}@{host}:{port}/{db_name}"
        elif db_type == "sqlite":
            url = f"sqlite:///{db_name}"
        elif db_type == "mssql":
            url = f"mssql+pymssql://{user}:{password}@{host}:{port}/{db_name}"
        elif db_type == "oracle":
            url = f"oracle+cx_oracle://{user}:{password}@{host}:{port}/?service_name={db_name}"
        elif db_type == "mariadb":
            url = f"mariadb+mariadbconnector://{user}:{password}@{host}:{port}/{db_name}"
        else:
            raise ValueError(f"Unsupported database type: {db_type}")

        engine = create_engine(url)

        # Attempt to connect to the database by opening and closing the connection
        with engine.connect() as connection:
            pass  # Successful connection

        return engine
    except OperationalError as e:
        # Database connection error
        return {"error": f"Error connecting to the database: {e}"}
    except Exception as e:
        return {"error": f"Error connecting to the database: {e}"}



def get_schema_info(engine):
    """
    Retrieves schema information from the database and annotates each column with PII details.
    Now supports both SQL databases and MongoDB.

    The merged PII definitions include:
      - General PII (e.g., name, email)
      - India-specific PII (e.g., pan, aadhaar)
      - Table-specific PII (e.g., phone_number, creditcard_number)

    Regex rules catch variations in column naming such as 'email_address', 'mobile', 'date_of_birth', etc.

    Returns:
        dict: Mapping of table names to a list of column info dictionaries.
    """
    try:
        # Single merged dictionary for exact PII definitions (keys are in lowercase)
        pii_columns = {
            # General PII definitions
            "name": {"sensitivity_level": "low"},
            "email": {"sensitivity_level": "high"},
            "phone": {"sensitivity_level": "medium"},
            "address": {"sensitivity_level": "medium"},
            "dob": {"sensitivity_level": "medium"},
            # India-specific PII definitions
            "pan": {"sensitivity_level": "high"},
            "aadhaar": {"sensitivity_level": "high"},
            "voter_id": {"sensitivity_level": "medium"},
            # Table-specific PII definitions (assuming column names are unique across tables)
            "phone_number": {"sensitivity_level": "medium"},
            "creditcard_number": {"sensitivity_level": "high"},
            "cvv": {"sensitivity_level": "high"},
            "expiry": {"sensitivity_level": "medium"},
            "issue_date": {"sensitivity_level": "medium"},
            "kyc_id": {"sensitivity_level": "low"},
        }

        # Define regex patterns to catch variations in column names.
        # Each tuple contains a compiled regex and the associated sensitivity level.
        regex_pii_rules = [
            (re.compile(r'email', re.IGNORECASE), "high"),
            (re.compile(r'phone|mobile', re.IGNORECASE), "medium"),
            (re.compile(r'address', re.IGNORECASE), "medium"),
            (re.compile(r'\bname\b', re.IGNORECASE), "low"),
            (re.compile(r'dob|date_of_birth', re.IGNORECASE), "medium"),
            (re.compile(r'pan', re.IGNORECASE), "high"),
            (re.compile(r'aadhaar', re.IGNORECASE), "high"),
            (re.compile(r'voter[_\s]?id', re.IGNORECASE), "medium"),
            (re.compile(r'credit[\s_]*card|creditcard', re.IGNORECASE), "high"),
            (re.compile(r'cvv', re.IGNORECASE), "high"),
            (re.compile(r'expiry', re.IGNORECASE), "medium"),
            (re.compile(r'issue[\s_]*date', re.IGNORECASE), "medium"),
            (re.compile(r'kyc[_]?id', re.IGNORECASE), "low"),
        ]

        
        # Check if the engine is a MongoDB database
        if isinstance(engine, type(MongoClient()['test'])):
            schema_info = {}
            # Get all collections in the database
            collections = engine.list_collection_names()
            
            for collection in collections:
                schema_info[collection] = []
                # Get a sample document to infer schema
                sample = engine[collection].find_one()
                if sample:
                    for field_name, value in sample.items():
                        # Skip MongoDB's internal _id field
                        if field_name == '_id':
                            continue
                            
                        # Determine field type
                        field_type = type(value).__name__
                        
                        # Check for PII using existing logic
                        normalized_field_name = field_name.strip().lower()
                        pii_info = None
                        
                        if normalized_field_name in pii_columns:
                            pii_info = pii_columns[normalized_field_name]
                        else:
                            for pattern, sensitivity in regex_pii_rules:
                                if pattern.search(field_name):
                                    pii_info = {"sensitivity_level": sensitivity}
                                    break
                                    
                        is_pii = pii_info is not None
                        sensitivity_level = pii_info["sensitivity_level"] if is_pii else None
                        
                        schema_info[collection].append({
                            "name": field_name,
                            "type": field_type,
                            "is_pii": is_pii,
                            "sensitivity_level": sensitivity_level,
                            "confidence": 0.9,
                        })
            return schema_info
            
        # For SQL databases, use existing logic
        inspector = inspect(engine)
        schema_info = {}

        # Fetch all table names from the database
        tables = inspector.get_table_names()

        # Process each table's columns
        for table in tables:
            schema_info[table] = []
            columns = inspector.get_columns(table)
            for column in columns:
                col_name = column["name"]
                pii_info = None

                # Normalize column name for exact matching (lowercase and stripped)
                normalized_col_name = col_name.strip().lower()

                # Check for an exact match in the merged dictionary first
                if normalized_col_name in pii_columns:
                    pii_info = pii_columns[normalized_col_name]
                else:
                    # If no exact match, apply regex rules to catch variations
                    for pattern, sensitivity in regex_pii_rules:
                        if pattern.search(col_name):
                            pii_info = {"sensitivity_level": sensitivity}
                            break

                is_pii = pii_info is not None
                sensitivity_level = pii_info["sensitivity_level"] if is_pii else None

                schema_info[table].append({
                    "name": col_name,
                    "type": str(column["type"]),
                    "is_pii": is_pii,
                    "sensitivity_level": sensitivity_level,
                    "confidence": 0.9,  # Fixed confidence value
                })
        return schema_info

    except Exception as e:
        return {"error": f"Error retrieving schema information: {e}"}
