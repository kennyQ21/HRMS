from sqlalchemy import create_engine, inspect, text
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
            url = f"oracle+oracledb://{user}:{password}@{host}:{port}/?service_name={db_name}"
        elif db_type == "mariadb":
            url = (
                f"mariadb+mariadbconnector://{user}:{password}@{host}:{port}/{db_name}"
            )
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


# Regex rules for column names (metadata) based on your PII definitions.
metadata_regex_rules = [
    (re.compile(r"\bname\b", re.IGNORECASE), "low"),
    (re.compile(r"\bemail\b", re.IGNORECASE), "high"),
    (re.compile(r"\b(phone|mobile)\b", re.IGNORECASE), "medium"),
    (re.compile(r"\baddress\b", re.IGNORECASE), "medium"),
    (re.compile(r"\b(dob|date_of_birth)\b", re.IGNORECASE), "medium"),
    (re.compile(r"\bpan\b", re.IGNORECASE), "high"),
    (re.compile(r"\baadhaar\b", re.IGNORECASE), "high"),
    (re.compile(r"\bvoter[_\s]?id\b", re.IGNORECASE), "medium"),
    (re.compile(r"\bcreditcard_number\b", re.IGNORECASE), "high"),
    (re.compile(r"\bcvv\b", re.IGNORECASE), "high"),
    (re.compile(r"\bexpiry\b", re.IGNORECASE), "medium"),
]

# Regex rules for actual data values.
data_pii_rules = [
    # Email addresses.
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "email",
        "high",
    ),
    # Phone numbers (US-style; adjust as needed).
    (re.compile(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "phone", "medium"),
    # Dates of birth in formats like MM/DD/YYYY or MM-DD-YYYY.
    (re.compile(r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b"), "dob", "medium"),
    # PAN: exactly 10 characters (5 letters, 4 digits, 1 letter).
    (re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), "pan", "high"),
    # Aadhaar: 12 digits, optionally with spaces.
    (re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "aadhaar", "high"),
    # Credit card number: a simple pattern for 13-16 digit sequences.
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "creditcard_number", "high"),
    # Expiry dates: formats like MM/YY or MM/YYYY.
    (re.compile(r"\b(0[1-9]|1[0-2])[/\-](\d{2}|\d{4})\b"), "expiry", "medium"),
    # CVV: 3 or 4 digits.
    (re.compile(r"\b\d{3,4}\b"), "cvv", "high"),
    # A basic pattern for addresses: number followed by street name and type.
    (
        re.compile(
            r"\d+\s+\w+(\s+\w+)*\s+(Street|St|Avenue|Ave|Road|Rd)\b", re.IGNORECASE
        ),
        "address",
        "medium",
    ),
]


def scan_columns_for_pii_sql(engine, mode="dual"):
    """
    Scans each table's columns using one of two approaches:
      - "metadata": Only scans the column names using regex rules.
      - "dual": Combines metadata scanning and data scanning on sample rows.

    Returns a dictionary mapping table names to lists of column info dicts.
    Each dict includes:
      - name: Column name.
      - metadata_confidence: 1.0 if column name indicates PII; 0 otherwise.
      - data_confidence: Fraction of sample rows matching a PII regex (0 if mode=="metadata").
      - overall_confidence: Set to 0.5 if only one detection source is positive, or 1.0 if both are detected.
      - is_pii: Boolean flag (True if overall_confidence > 0).
      - sensitivity_level: Determined from metadata if available; otherwise from data scan.
    """
    inspector = inspect(engine)
    results = {}

    for table in inspector.get_table_names():
        results[table] = []
        columns = inspector.get_columns(table)
        for column in columns:
            col_name = column["name"]

            # ----- Metadata scanning using regex for column names -----
            metadata_confidence = 0
            metadata_sensitivity = None
            for pattern, sensitivity in metadata_regex_rules:
                if pattern.search(col_name):
                    metadata_confidence = 1.0
                    metadata_sensitivity = sensitivity
                    break

            # ----- Data scanning on a sample of rows (only if mode is "dual") -----
            data_confidence = 0
            data_sensitivity = None
            if mode == "dual":
                sample_query = text(f'SELECT "{col_name}" FROM "{table}" LIMIT 5')
                try:
                    with engine.connect() as connection:
                        result = connection.execute(sample_query)
                        rows = result.fetchall()
                except Exception as e:
                    print(
                        f"Error fetching sample rows for column {col_name} in table {table}: {e}"
                    )
                    rows = []
                match_count = 0
                for row in rows:
                    cell_value = str(row[0]) if row[0] is not None else ""
                    for pattern, pii_type, sensitivity in data_pii_rules:
                        if pattern.search(cell_value):
                            match_count += 1
                            if data_sensitivity is None:
                                data_sensitivity = sensitivity
                            break
                total_samples = len(rows)
                data_confidence = (
                    (match_count / total_samples) if total_samples > 0 else 0
                )

            # ----- Combine detections: set overall confidence 0.5 if only one source detected, 1.0 if both -----
            detected_sources = (1 if metadata_confidence > 0 else 0) + (
                1 if data_confidence > 0 else 0
            )
            if detected_sources == 0:
                overall_confidence = 0
            elif detected_sources == 1:
                overall_confidence = 0.5
            else:
                overall_confidence = 1.0

            is_pii = overall_confidence > 0
            sensitivity_level = (
                metadata_sensitivity
                if metadata_sensitivity is not None
                else data_sensitivity
            )

            results[table].append(
                {
                    "name": col_name,
                    "metadata_confidence": metadata_confidence,
                    "data_confidence": data_confidence,
                    "overall_confidence": overall_confidence,
                    "is_pii": is_pii,
                    "sensitivity_level": sensitivity_level,
                }
            )
    return results


def scan_columns_for_pii_mongo(db, mode="dual"):
    """
    Scans MongoDB collections for PII using pymongo's native sampling.
    Sample size is dynamically adjusted based on collection size.

    Args:
        db: MongoDB database connection
        mode: "metadata" for column names only, "dual" for names and data scanning

    Returns:
        Dictionary mapping collection names to lists of field info dicts
    """
    results = {}

    for collection_name in db.list_collection_names():
        collection = db[collection_name]
        results[collection_name] = []

        # Determine sample size based on collection size
        total_docs = collection.estimated_document_count()
        if total_docs < 100:
            sample_size = total_docs
        elif total_docs < 10000:
            sample_size = max(100, total_docs // 10)
        else:
            sample_size = min(1000 + int(100 * (total_docs ** 0.5)), 5000)


        # Get sample documents
        try:
            pipeline = [{"$sample": {"size": sample_size}}]
            sample_docs = list(collection.aggregate(pipeline))
        except Exception as e:
            print(f"Error sampling documents from collection {collection_name}: {e}")
            continue

        # Extract all field paths from sample documents
        field_paths = set()
        for doc in sample_docs:
            field_paths.update(get_field_paths(doc))

        # Process each field
        for field_path in field_paths:
            metadata_confidence = 0
            metadata_sensitivity = None

            # Check field name against PII patterns
            for pattern, sensitivity in metadata_regex_rules:
                if pattern.search(field_path):
                    metadata_confidence = 1.0
                    metadata_sensitivity = sensitivity
                    break

            # Data scanning if mode is "dual"
            data_confidence = 0
            data_sensitivity = None
            if mode == "dual":
                match_count = 0
                sample_count = min(5, len(sample_docs))
                for doc in sample_docs[:sample_count]:
                    # Get nested field value using dot notation
                    field_value = get_nested_value(doc, field_path)
                    field_value = str(field_value) if field_value is not None else ""
                    
                    for pattern, pii_type, sensitivity in data_pii_rules:
                        if pattern.search(field_value):
                            match_count += 1
                            if data_sensitivity is None:
                                data_sensitivity = sensitivity
                            break

                data_confidence = match_count / sample_count if sample_count > 0 else 0

            # Calculate overall confidence
            detected_sources = (1 if metadata_confidence > 0 else 0) + (1 if data_confidence > 0 else 0)
            if detected_sources == 0:
                overall_confidence = 0
            elif detected_sources == 1:
                overall_confidence = 0.5
            else:
                overall_confidence = 1.0

            is_pii = overall_confidence > 0
            sensitivity_level = metadata_sensitivity if metadata_sensitivity is not None else data_sensitivity

            # Determine field type from sample values
            field_type = get_field_type(sample_docs[:5], field_path)

            results[collection_name].append({
                "name": field_path,
                "metadata_confidence": metadata_confidence,
                "data_confidence": data_confidence,
                "overall_confidence": overall_confidence,
                "is_pii": is_pii,
                "sensitivity_level": sensitivity_level,
                "field_type": field_type
            })

    return results

def get_field_paths(doc, parent_path="", paths=None):
    """
    Recursively get all field paths in a document using dot notation.
    """
    if paths is None:
        paths = set()
    
    for key, value in doc.items():
        current_path = f"{parent_path}.{key}" if parent_path else key
        paths.add(current_path)
        
        if isinstance(value, dict):
            get_field_paths(value, current_path, paths)
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            get_field_paths(value[0], current_path, paths)
    
    return paths

def get_nested_value(doc, field_path):
    """
    Get value from nested document using dot notation.
    """
    value = doc
    for key in field_path.split('.'):
        if isinstance(value, dict):
            value = value.get(key)
        else:
            return None
    return value

def get_field_type(docs, field_path):
    """
    Determine field type from sample documents.
    """
    types = set()
    for doc in docs:
        value = get_nested_value(doc, field_path)
        if value is not None:
            if isinstance(value, (list, tuple)):
                types.add("array")
            elif isinstance(value, dict):
                types.add("object")
            elif isinstance(value, bool):
                types.add("boolean")
            elif isinstance(value, int):
                types.add("integer")
            elif isinstance(value, float):
                types.add("number")
            elif isinstance(value, str):
                types.add("string")
            else:
                types.add("unknown")
    
    return list(types)[0] if types else "unknown"
