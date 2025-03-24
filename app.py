import os
from flask import Flask, jsonify, request
from sqlalchemy import MetaData
from flask_cors import CORS
from db_utils import connect_to_db, scan_columns_for_pii_sql, scan_columns_for_pii_mongo
from sqlalchemy import select
import requests
import time
from datetime import date, datetime
import uuid
from bson.objectid import ObjectId
from constants import PII_TYPES, PIIType
from sqlalchemy.orm import sessionmaker
from models import ColumnScan, ScanAnomaly, Scan, engine
import re
from typing import List, Tuple
from collections import defaultdict
from parsers.structured.excel_parser import ExcelParser
from parsers.structured.csv_parser import CSVParser
from parsers.unstructured.document_parser import DocumentParser
from parsers.unstructured.document_parser import PDFParser
from parsers.unstructured.access_parser import MDBParser
from parsers.unstructured.sql_parser import SQLParser
from werkzeug.utils import secure_filename



app = Flask(__name__)
CORS(app)
app.config["DEBUG"] = os.getenv("FLASK_ENV") == "development"

Session = sessionmaker(bind=engine)


@app.route("/check-connection", methods=["POST", "OPTIONS"])
def check_connection():
    if request.method == "OPTIONS":
        # CORS preflight request, just return OK (200)
        return '', 200

    data = request.json
    db_type = data.get("db_type")
    db_name = data.get("db_name")
    user = data.get("user")
    password = data.get("password")
    host = data.get("host", "localhost")
    port = data.get("port", None)

    # Check if essential parameters are provided
    if not db_type or not db_name:
        return jsonify({"error": "Missing database type or database name"}), 400

    # Attempt to connect to the database
    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        # Return a 400 Bad Request if connection cannot be established due to input-related issues
        return jsonify({
            "error": "Cannot establish connection",
            "details": engine["error"]
        }), 400

    return jsonify({"message": "Connection successful"}), 200


@app.route("/get-schema", methods=["POST", "OPTIONS"])  
def get_schema():
    if request.method == "OPTIONS":
        # CORS preflight request, just return OK (200)
        return '', 200

    data = request.json
    db_type = data.get("db_type")
    db_name = data.get("db_name")
    user = data.get("user")
    password = data.get("password")
    host = data.get("host", "localhost")
    port = data.get("port", None)
    scan_type = data.get("scan_type", "metadata")

    if not db_type or not db_name:
        return jsonify({"error": "Missing database type or database name"}), 400

    # Connect to the database
    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        return jsonify(engine), 500
    if db_type=="postgres" or db_type==("oracle"):
        schema_info = scan_columns_for_pii_sql(engine,scan_type)
    elif db_type.startswith("mongodb"):
        schema_info = scan_columns_for_pii_mongo(engine,scan_type)
    return jsonify(schema_info)


def serialize_data(data):
    """Recursively convert dates and UUIDs to strings in the data."""
    if isinstance(data, dict):
        return {key: serialize_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [serialize_data(item) for item in data]
    elif isinstance(data, (date, datetime)):
        return data.isoformat()  # Convert date/datetime to ISO 8601 string
    elif isinstance(data, uuid.UUID):
        return str(data)  # Convert UUID to string
    else:
        return data


@app.route("/get-table-data", methods=["POST"])
def get_table_data():
    data = request.json

    db_type = data.get("db_type")
    db_name = data.get("db_name")
    user = data.get("user")
    password = data.get("password")
    host = data.get("host", "localhost")
    port = data.get("port", None)
    table_name = data.get("table_name")  # For MongoDB, this will be collection name
    selected_columns = data.get("selected_columns", [])
    vault_name = data.get("vault_name")

    # Retrieve Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    # Extract Bearer token
    token = auth_header.split(" ")[1]

    if not db_type or not db_name or not table_name or not vault_name:
        return jsonify({"error": "Missing database type, database name, table name, or vault name"}), 400

    # Connect to database
    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        return jsonify(engine), 500

    try:
        # Handle MongoDB differently from SQL databases
        if db_type.startswith("mongodb"):
            # For MongoDB, engine is actually the database object
            collection = engine[table_name]
            
            # Build projection for selected columns
            projection = None
            if selected_columns:
                projection = {col: 1 for col in selected_columns}
                # Always include _id unless explicitly excluded
                if "_id" not in selected_columns:
                    projection["_id"] = 0

            # Fetch documents
            cursor = collection.find({}, projection)
            table_data = list(cursor)

            # Convert MongoDB ObjectId to string if present
            for doc in table_data:
                if "_id" in doc and isinstance(doc["_id"], ObjectId):
                    doc["_id"] = str(doc["_id"])

        else:
            # Existing SQL database logic
            metadata = MetaData()
            metadata.reflect(bind=engine)

            table = metadata.tables.get(table_name)
            if table is None:
                return jsonify({"error": f"Table '{table_name}' not found"}), 404

            conn = engine.connect()

            # Create the query with selected columns
            if selected_columns:
                query = select(*[table.c[column] for column in selected_columns])
            else:
                query = select(table)  # Select all columns if none specified

            result = conn.execute(query)
            rows = result.fetchall()

            # Convert rows to a list of dictionaries
            column_names = selected_columns if selected_columns else table.columns.keys()
            table_data = [dict(zip(column_names, row)) for row in rows]

            conn.close()

        # Serialize data to handle date and datetime objects
        serialized_data = serialize_data(table_data)

        # Send the data to the ingestion URL with Bearer token in headers
        ingestion_url = f"https://policyengine.getpatronus.com/api/vault/vaults/{vault_name}/records/multiple"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        ingestion_response = requests.post(ingestion_url, json={"data": serialized_data}, headers=headers)

        # Check if the ingestion request was successful
        if ingestion_response.status_code != 201:
            return jsonify({"error": "Failed to ingest data", "details": ingestion_response.text}), 500

        return jsonify({
            "table": table_name,
            "data": serialized_data,
            "ingestion_status": ingestion_response.json()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/get-table-data", methods=["POST"])
def benchmark_get_table_data():
    data = request.json

    db_type = data.get("db_type")
    db_name = data.get("db_name")
    user = data.get("user")
    password = data.get("password")
    host = data.get("host", "localhost")
    port = data.get("port", None)
    table_name = data.get("table_name")
    selected_columns = data.get("selected_columns", [])

    if not db_type or not db_name or not table_name:
        return (
            jsonify({"error": "Missing database type, database name, or table name"}),
            400,
        )

    # Step 1: Connect to DB
    start_time = time.time()
    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        return jsonify(engine), 500
    db_connection_time = time.time() - start_time

    try:
        # Step 2: Reflect Metadata
        start_time = time.time()
        metadata = MetaData()
        metadata.reflect(bind=engine)
        reflection_time = time.time() - start_time

        # Step 3: Access Table
        start_time = time.time()
        table = metadata.tables.get(table_name)
        if table is None:
            return jsonify({"error": f"Table '{table_name}' not found"}), 404
        table_access_time = time.time() - start_time

        # Step 4: Execute Query
        conn = engine.connect()
        start_time = time.time()
        
        if selected_columns:
            query = select(*[table.c[column] for column in selected_columns])
        else:
            query = select(table)
        
        result = conn.execute(query)
        rows = result.fetchall()
        query_execution_time = time.time() - start_time

        # Step 5: Process Data
        start_time = time.time()
        column_names = selected_columns if selected_columns else table.columns.keys()
        table_data = [dict(zip(column_names, row)) for row in rows]
        data_processing_time = time.time() - start_time

        conn.close()

        # Total time
        total_time = db_connection_time + reflection_time + table_access_time + query_execution_time + data_processing_time

        return jsonify({
            "table": table_name,
            "data": table_data,
            "benchmark": {
                "db_connection_time": db_connection_time,
                "reflection_time": reflection_time,
                "table_access_time": table_access_time,
                "query_execution_time": query_execution_time,
                "data_processing_time": data_processing_time,
                "total_time": total_time
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/ingest-table-data", methods=["POST", "OPTIONS"])
def ingest_table_data():
    if request.method == "OPTIONS":
        return '', 200

    data = request.json
    db_type = data.get("db_type")
    db_name = data.get("db_name")
    user = data.get("user")
    password = data.get("password")
    host = data.get("host", "localhost")
    port = data.get("port", None)
    tables_info = data.get("tables_info", [])
    join_key = data.get("join_key", "id")

    if not db_type or not db_name or not tables_info:
        return jsonify({"error": "Missing database type, database name, or table information"}), 400

    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        return jsonify(engine), 422

    try:
        if db_type.startswith("mongodb"):
            # MongoDB logic
            base_collection_info = tables_info[0]
            base_collection = engine[base_collection_info["table_name"]]
            
            # Create projection from requested columns
            base_projection = {col: 1 for col in base_collection_info.get("columns", [])} if base_collection_info.get("columns") else None
            if base_projection and join_key not in base_projection:
                base_projection[join_key] = 1

            # Get base documents
            base_docs = list(base_collection.find({}, base_projection))
            
            # Create a lookup dictionary for documents by join key
            merged_data = {str(doc.get(join_key)): doc for doc in base_docs if join_key in doc}

            # Merge data from additional collections
            for collection_info in tables_info[1:]:
                collection = engine[collection_info["table_name"]]
                projection = {col: 1 for col in collection_info.get("columns", [])} if collection_info.get("columns") else None
                if projection:
                    projection[join_key] = 1

                # Get documents from current collection
                docs = collection.find({}, projection)
                
                # Merge documents based on join key
                for doc in docs:
                    doc_join_key = str(doc.get(join_key))
                    if doc_join_key in merged_data:
                        merged_data[doc_join_key].update({k: v for k, v in doc.items() if k != join_key})

            # Convert merged data to list and handle ObjectId serialization
            serialized_data = []
            for doc in merged_data.values():
                serialized_doc = {}
                for k, v in doc.items():
                    if isinstance(v, ObjectId):
                        serialized_doc[k] = str(v)
                    else:
                        serialized_doc[k] = v
                serialized_data.append(serialized_doc)

        else:
            # SQL logic
            metadata = MetaData()
            metadata.reflect(bind=engine)
            
            base_table_info = tables_info[0]
            base_table = metadata.tables.get(base_table_info["table_name"])

            if base_table is None:
                return jsonify({"error": f"Table '{base_table_info['table_name']}' not found"}), 404

            base_columns = [
                base_table.c[col] for col in base_table_info["columns"]
                if col in base_table.c
            ] if base_table_info.get("columns") else [base_table]

            if not base_columns:
                return jsonify({"error": f"No valid columns specified for table '{base_table_info['table_name']}'"}), 400

            query = select(*base_columns).select_from(base_table)

            for table_info in tables_info[1:]:
                table = metadata.tables.get(table_info["table_name"])
                if table is None:
                    return jsonify({"error": f"Table '{table_info['table_name']}' not found"}), 404

                columns = [table.c[col] for col in table_info["columns"] if col in table.c] if table_info.get("columns") else [table]

                if not columns:
                    return jsonify({"error": f"No valid columns specified for table '{table_info['table_name']}'"}), 400

                if join_key in table.c:
                    query = query.add_columns(*columns).outerjoin(
                        table,
                        base_table.c[join_key] == table.c[join_key]
                    )
                else:
                    query = query.add_columns(*columns)

            with engine.connect() as conn:
                result = conn.execute(query)
                rows = result.fetchall()

            unique_data = {}
            for row in rows:
                row_dict = {key: serialize_data(value) for key, value in row._mapping.items()}
                join_key_value = row_dict.get(join_key)
                if join_key_value is not None:
                    row_dict['_id'] = str(join_key_value)  # Use join_key as _id for SQL data
                    unique_data[join_key_value] = serialize_data(row_dict)

            serialized_data = list(unique_data.values())

        # Common ingestion logic
        columns_count = len(serialized_data[0].keys()) if serialized_data else 0
        max_batch_size = 65535 // max(columns_count, 1)

        ingestion_url = f"https://policyengine.getpatronus.com/api/vault/vaults/{data['vault_name']}/records/multiple"
        headers = {
            "Authorization": f"Bearer {request.headers.get('Authorization').split()[1]}",
            "Content-Type": "application/json"
        }

        for i in range(0, len(serialized_data), max_batch_size):
            batch_data = serialized_data[i:i + max_batch_size]
            ingestion_response = requests.post(ingestion_url, json={"data": batch_data}, headers=headers)

            if ingestion_response.status_code != 201:
                return jsonify({"error": "Failed to ingest data", "details": ingestion_response.text}), 422

        return jsonify({"ingestion_status": "All batches ingested successfully"})

    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 400


@app.route("/get-pii-types", methods=["GET", "OPTIONS"])
def get_pii_types():
    """
    Get all PII types and their metadata.
    Returns a JSON array of PII type definitions.
    """
    if request.method == "OPTIONS":
        # CORS preflight request, just return OK (200)
        return '', 200
    
    # Convert Enum values to strings for JSON serialization
    serialized_pii_types = []
    for pii_type in PII_TYPES:
        serialized_type = {
            'id': pii_type['id'],
            'name': pii_type['name'],
            'description': pii_type['description'],
            'category': pii_type['category'].value,
            'sensitivity': pii_type['sensitivity'].value
        }
        serialized_pii_types.append(serialized_type)
    
    return jsonify(serialized_pii_types)


def check_pii_matches(value: str, pii_types: List[PIIType]) -> List[Tuple[str, bool]]:
    """Check a value against all PII regex patterns."""
    matches = []
    for pii_type in pii_types:
        if 'regex' in pii_type:
            try:
                pattern = re.compile(pii_type['regex'])
                matches.append((pii_type['id'], bool(pattern.match(str(value)))))
            except:
                continue
    return matches


@app.route("/scan-database", methods=["POST"])
def scan_database():
    """Scan database for PII and store results."""
    data = request.json
    db_type = data.get("db_type")
    db_name = data.get("db_name")
    user = data.get("user")
    password = data.get("password")
    host = data.get("host", "localhost")
    port = data.get("port", None)
    connector_id = data.get("connector_id")
    pii_ids = data.get("pii_ids", [])
    scan_name = data.get("scan_name")

    if not all([db_type, db_name, connector_id]):
        return jsonify({"error": "Missing required parameters"}), 400

    # Filter PII_TYPES based on provided pii_ids
    selected_pii_types = [pii for pii in PII_TYPES if pii['id'] in pii_ids] if pii_ids else PII_TYPES

    # Connect to the target database
    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        return jsonify(engine), 500

    session = Session()

    try:
          # Delete old scans with the same connector_id
        old_scans = session.query(Scan).filter(Scan.connector_id == connector_id).all()
        for old_scan in old_scans:
            session.delete(old_scan)
        session.commit()

           # Create a new scan record
        scan = Scan(
            name=scan_name,
            connector_id=connector_id
        )
        session.add(scan)
        session.flush()  # Get scan.id

        scan_results = []  # To collect results

        if db_type.startswith("mongodb"):
            # MongoDB scanning logic
            collections = engine.list_collection_names()
            for collection_name in collections:
                collection = engine[collection_name]
                sample_docs = list(collection.find().limit(1000))
                
                fields = set()
                for doc in sample_docs:
                    fields.update(doc.keys())

                for field in fields:
                    field_values = [doc.get(field) for doc in sample_docs if field in doc]
                    result = process_column_data(session, connector_id, db_name, collection_name, field, field_values, selected_pii_types)
                    scan_results.append(result)

        else:
            # SQL database scanning logic
            metadata = MetaData()
            metadata.reflect(bind=engine)

            for table_name, table in metadata.tables.items():
                query = select(table).limit(1000)
                with engine.connect() as conn:
                    result = conn.execute(query)
                    rows = [dict(row._mapping) for row in result]
                    
                    for column in table.columns:
                        column_values = [row.get(column.name) for row in rows]
                        result = process_column_data(session, scan, connector_id, db_name, table_name, column.name, column_values, selected_pii_types)
                        scan_results.append(result)

        session.commit()
        return jsonify({
            "message": "Scan completed successfully",
            "scan_id": scan.id
        })

    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()

def process_column_data(session, scan : Scan, connector_id: str, db_name: str, table_name: str, column_name: str, values: List[any], pii_types: List[PIIType]):
    """Process and store column data scanning results."""
    try:
        pii_matches = defaultdict(int)
        total_rows = len(values)
        
        # Initialize primary_pii with default values
        primary_pii = (None, 0)  # (pii_id, match_count)
        
        # Count matches for each PII type
        for value in values:
            if value is not None:
                matches = check_pii_matches(str(value), pii_types)
                for pii_id, matched in matches:
                    if matched:
                        pii_matches[pii_id] += 1

        # Find primary PII type (highest match count)
        for pii_id, match_count in pii_matches.items():
            if match_count / total_rows > 0.5:  # More than 50% match rate
                if match_count > primary_pii[1]:
                    primary_pii = (pii_id, match_count)

        # Create column scan record
        column_scan = ColumnScan(
            db_name=db_name,
            table_name=table_name,
            column_name=column_name,
            total_rows=total_rows,
            primary_pii_type=primary_pii[0],
            primary_pii_match_count=primary_pii[1],
            scan=scan
        )
        
        session.add(column_scan)
        session.flush()  # This will populate the id field
        

        for pii_id, match_count in pii_matches.items():
            if pii_id != primary_pii[0] and match_count > 0:
                confidence_score = match_count / total_rows
                anomaly = ScanAnomaly(
                    pii_type=pii_id,
                    match_count=match_count,
                    confidence_score=confidence_score,
                    column_scan=column_scan
                )
                session.add(anomaly)
        
    except Exception as e:
        print(f"Error processing column {column_name}: {str(e)}")
        raise


@app.route("/get-scan-results/<int:scan_id>", methods=["GET"])
def get_scan_results(scan_id):
    """Get the scanning results and anomalies for a specific scan ID."""
    if request.method == "OPTIONS":
        # CORS preflight request, just return OK (200)
        return '', 200
    
    session = Session()
    try:
        # Query the Scan model first
        scan = session.query(Scan).filter(Scan.id == scan_id).first()

        if not scan:
            return jsonify({"error": "No scan found with this ID"}), 404

        # Get all column scans for this scan
        column_scans = scan.column_scans

        # Prepare the response data
        scan_data = {
            "scan_id": scan.id,
            "scan_name": scan.name,
            "connector_id": scan.connector_id,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "columns": []
        }

        # Totals across all columns
        pii_type_totals = defaultdict(int)

        # Process each column scan
        for column_scan in column_scans:
            # Add primary PII to totals
            if column_scan.primary_pii_type and column_scan.primary_pii_match_count:
                pii_type_totals[column_scan.primary_pii_type] += column_scan.primary_pii_match_count

            # Add anomalies to totals
            for anomaly in column_scan.anomalies:
                pii_type_totals[anomaly.pii_type] += anomaly.match_count

            # Create column data
            column_data = {
                "id": column_scan.id,
                "db_name": column_scan.db_name,
                "table_name": column_scan.table_name,
                "column_name": column_scan.column_name,
                "total_rows": column_scan.total_rows,
                "primary_pii_type": column_scan.primary_pii_type,
                "primary_pii_match_count": column_scan.primary_pii_match_count,
                "anomalies": [
                    {
                        "pii_type": anomaly.pii_type,
                        "match_count": anomaly.match_count,
                        "confidence_score": round(anomaly.confidence_score, 3)
                    }
                    for anomaly in column_scan.anomalies
                ]
            }
            
            scan_data["columns"].append(column_data)

        return jsonify({
            "pii_type_totals": dict(pii_type_totals),
            "scan_result": scan_data
        })

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

    finally:
        session.close()


@app.route("/get-scans", methods=["GET", "OPTIONS"])
def get_scans():
    """Get a list of all scans with basic details."""
    if request.method == "OPTIONS":
        # CORS preflight request, just return OK (200)
        return '', 200
    
    session = Session()
    try:
        # Query all scans
        scans = session.query(Scan).order_by(Scan.created_at.desc()).all()
        
        # Format the response
        scans_list = []
        for scan in scans:
            scans_list.append({
                "id": scan.id,
                "name": scan.name,
                "connector_id": scan.connector_id,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "column_count": len(scan.column_scans)  # Include count of columns scanned
            })
        
        return jsonify({
            "scans": scans_list,
            "total": len(scans_list)
        })
        
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    
    finally:
        session.close()

import re
from typing import List, Dict, Tuple, Any
from collections import defaultdict
def process_document_content(session, scan, connector_id: str, db_name: str, text_content: str, pii_types: List[PIIType]):
    """Process and store document content scanning results."""
    pii_matches = defaultdict(int)
    total_rows = 1  
    
    for pii_type in pii_types:
        pattern = re.compile(pii_type['regex'])
        
        matches = pattern.findall(text_content)
        match_count = len(matches)
        
        if match_count > 0:
            print(f"Found {match_count} matches for {pii_type['name']}: {matches[:3]}")
        
        if match_count > 0:
            pii_matches[pii_type['id']] = match_count
    
    primary_pii = (None, 0)  # (pii_id, match_count)
    for pii_id, match_count in pii_matches.items():
        if match_count > primary_pii[1]:
            primary_pii = (pii_id, match_count)
    
    column_scan = ColumnScan(
        db_name=db_name,
        table_name="document",
        column_name="content",
        total_rows=total_rows,
        primary_pii_type=primary_pii[0],
        primary_pii_match_count=primary_pii[1],
        scan=scan
    )
    
    session.add(column_scan)
    session.flush()
    
    for pii_id, match_count in pii_matches.items():
        if pii_id != primary_pii[0] and match_count > 0:
            confidence_score = match_count / 100.0
            anomaly = ScanAnomaly(
                pii_type=pii_id,
                match_count=match_count,
                confidence_score=confidence_score,
                column_scan=column_scan
            )
            session.add(anomaly)
    
    return column_scan

@app.route("/scan-file", methods=["POST"])
def scan_file():
    """Scan files including those in ZIP archives and return structured data"""
    # Import ALL required modules at the top of the function
    import os
    import tempfile
    import zipfile
    import shutil
    from datetime import datetime
    from werkzeug.utils import secure_filename
    from collections import defaultdict
    import re
    import PyPDF2
    
    # Check for PyCryptodome for handling encrypted PDFs
    try:
        import Crypto
    except ImportError:
        # We'll handle this later if we encounter an encrypted PDF
        pass
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    filename = file.filename.lower()
    
    # Get password parameters if provided
    password = request.form.get('password', None)
    
    session = Session()
    all_scan_results = []
    
    try:
        # Save file temporarily
        temp_upload_path = f"/tmp/{secure_filename(file.filename)}"
        file.save(temp_upload_path)
        
        # Create scan record
        scan = Scan(
            name=f"File_Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            connector_id=f"file_upload"
        )
        session.add(scan)
        session.flush()
        
        if filename.endswith('.zip'):
            extract_dir = tempfile.mkdtemp(prefix="zip_extract_")
            
            try:
                with zipfile.ZipFile(temp_upload_path, 'r') as zip_ref:
                    # Check if file is password protected
                    is_encrypted = any(zi.flag_bits & 0x1 for zi in zip_ref.filelist)
                    
                    if is_encrypted and not password:
                        return jsonify({'error': 'ZIP file is password protected. Please provide a password.'}), 400
                    
                    try:
                        # Extract with password if provided and needed
                        if is_encrypted:
                            zip_ref.extractall( pwd=password.encode('utf-8'))
                        else:
                            zip_ref.extractall(extract_dir)
                    except RuntimeError as e:
                        if "Bad password" in str(e):
                            return jsonify({'error': 'Incorrect ZIP password'}), 401
                        raise
                
                for root, _, files in os.walk(extract_dir):
                    for extracted_file in files:
                        extracted_path = os.path.join(root, extracted_file)
                        extracted_filename = extracted_file.lower()
                        
                        # Process each file based on its type
                        if extracted_filename.endswith(('.xlsx', '.xls')):
                            parser = ExcelParser()
                        elif extracted_filename.endswith('.csv'):
                            parser = CSVParser()
                        elif extracted_filename.endswith(('.docx', '.doc', '.odt', '.rtf')):
                            parser = DocumentParser()
                        elif extracted_filename.endswith('.pdf'):
                            parser = PDFParser(password=password)
                        elif extracted_filename.endswith('.mdb'):
                            parser = MDBParser()
                        elif extracted_filename.endswith('.sql'):
                            parser = SQLParser()
                        else:
                            all_scan_results.append({
                                'filename': extracted_filename,
                                'status': 'skipped',
                                'reason': 'Unsupported file format'
                            })
                            continue
                        
                        try:
                            # Parse file
                            parsed_data = parser.parse(extracted_path)
                            
                            if not parser.validate(parsed_data):
                                all_scan_results.append({
                                    'filename': extracted_filename,
                                    'status': 'error',
                                    'error': 'Invalid file structure'
                                })
                                continue
                            
                            # Process based on file type
                            if extracted_filename.endswith(('.pdf', '.docx', '.doc', '.odt', '.rtf')):
                                text_content = parsed_data['data'][0].get('content', '')
                                process_document_content(
                                    session,
                                    scan,
                                    f"{extracted_filename.split('.')[-1]}_parser",
                                    os.path.basename(extracted_filename),
                                    text_content,
                                    PII_TYPES
                                )
                            elif extracted_filename.endswith('.sql'):
                                for item in parsed_data['data']:
                                    content_type = item.get('content_type', '')
                                    text_content = item.get('content', '')
                                    
                                    if content_type == 'full_sql':
                                        process_document_content(
                                            session,
                                            scan,
                                            "sql_parser",
                                            os.path.basename(extracted_filename),
                                            text_content,
                                            PII_TYPES
                                        )
                                    elif content_type == 'table_definition':
                                        table_name = item.get('table_name', 'unknown_table')
                                        process_document_content(
                                            session,
                                            scan,
                                            "sql_parser",
                                            os.path.basename(extracted_filename),
                                            f"Table {table_name}: {text_content}",
                                            PII_TYPES
                                        )
                            elif extracted_filename.endswith('.mdb'):
                                for table_data in parsed_data['data']:
                                    table_name = table_data['table_name']
                                    for column in table_data['columns']:
                                        column_values = [row.get(column) for row in table_data['rows']]
                                        process_column_data(
                                            session, 
                                            scan,
                                            "mdb_parser",
                                            os.path.basename(extracted_filename),
                                            table_name,
                                            column,
                                            column_values,
                                            PII_TYPES
                                        )
                            else:
                                for column in parsed_data['metadata']['columns']:
                                    column_values = [row.get(column) for row in parsed_data['data']]
                                    process_column_data(
                                        session, 
                                        scan,
                                        f"{extracted_filename.split('.')[-1]}_parser",
                                        os.path.basename(extracted_filename),
                                        "sheet1" if extracted_filename.endswith(('.xlsx', '.xls')) else "data",
                                        column,
                                        column_values,
                                        PII_TYPES
                                    )
                                
                            all_scan_results.append({
                                'filename': extracted_filename,
                                'status': 'success',
                                'metadata': parsed_data['metadata']
                            })
                                
                        except Exception as file_error:
                            error_message = str(file_error)
                            if "password required" in error_message.lower() or "incorrect password" in error_message.lower():
                                error_message = f"Password protected file. Please provide the correct password."
                            
                            print(f"Error processing {extracted_filename}: {error_message}")
                            all_scan_results.append({
                                'filename': extracted_filename,
                                'status': 'error',
                                'error': error_message
                            })
                
            finally:
                shutil.rmtree(extract_dir, ignore_errors=True)
        else:
            # Process single file
            if filename.endswith(('.xlsx', '.xls')):
                parser = ExcelParser()
            elif filename.endswith('.csv'):
                parser = CSVParser()
            elif filename.endswith(('.docx', '.doc', '.odt', '.rtf')):
                parser = DocumentParser()
            elif filename.endswith('.pdf'):
                is_pdf_protected = check_pdf_is_protected(temp_upload_path)
                if is_pdf_protected and not password:
                    return jsonify({'error': 'PDF is password protected. Please provide a password.'}), 400
                
                parser = PDFParser(password=password)
            elif filename.endswith('.mdb'):
                parser = MDBParser()
            elif filename.endswith('.sql'):
                parser = SQLParser()
            else:
                return jsonify({'error': 'Unsupported file format'}), 400
            
            try:
                # Parse file
                parsed_data = parser.parse(temp_upload_path)
                
                if not parser.validate(parsed_data):
                    raise ValueError("Invalid file structure")
                
                # Process based on file type
                if filename.endswith(('.pdf', '.docx', '.doc', '.odt', '.rtf')):
                    text_content = parsed_data['data'][0].get('content', '')
                    process_document_content(
                        session,
                        scan,
                        f"{filename.split('.')[-1]}_parser",
                        os.path.basename(filename),
                        text_content,
                        PII_TYPES
                    )
                elif filename.endswith('.sql'):
                    for item in parsed_data['data']:
                        content_type = item.get('content_type', '')
                        text_content = item.get('content', '')
                        
                        if content_type == 'full_sql':
                            process_document_content(
                                session,
                                scan,
                                "sql_parser",
                                os.path.basename(filename),
                                text_content,
                                PII_TYPES
                            )
                        elif content_type == 'table_definition':
                            table_name = item.get('table_name', 'unknown_table')
                            process_document_content(
                                session,
                                scan,
                                "sql_parser",
                                os.path.basename(filename),
                                f"Table {table_name}: {text_content}",
                                PII_TYPES
                            )
                elif filename.endswith('.mdb'):
                    for table_data in parsed_data['data']:
                        table_name = table_data['table_name']
                        for column in table_data['columns']:
                            column_values = [row.get(column) for row in table_data['rows']]
                            process_column_data(
                                session, 
                                scan,
                                "mdb_parser",
                                os.path.basename(filename),
                                table_name,
                                column,
                                column_values,
                                PII_TYPES
                            )
                else:
                    for column in parsed_data['metadata']['columns']:
                        column_values = [row.get(column) for row in parsed_data['data']]
                        process_column_data(
                            session, 
                            scan,
                            f"{filename.split('.')[-1]}_parser",
                            os.path.basename(filename),
                            "sheet1" if filename.endswith(('.xlsx', '.xls')) else "data",
                            column,
                            column_values,
                            PII_TYPES
                        )
                
                all_scan_results.append({
                    'filename': filename,
                    'status': 'success',
                    'metadata': parsed_data['metadata']
                })
                
            except Exception as e:
                error_message = str(e)
                if "password required" in error_message.lower() or "incorrect password" in error_message.lower():
                    return jsonify({'error': 'Password protected file. Please provide the correct password.'}), 401
                raise
        
        # Clean up
        os.remove(temp_upload_path)
        
        session.commit()
        
        return jsonify({
            'status': 'success',
            'scan_id': scan.id,
            'file_count': len(all_scan_results),
            'results': all_scan_results
        })
        
    except Exception as e:
        session.rollback()
        error_message = str(e)
        
        # Handle specific errors with informative messages
        if "PyCryptodome is required" in error_message:
            return jsonify({
                'error': 'Missing dependency: PyCryptodome is required for encrypted PDFs',
                'solution': 'Please install with: pip install pycryptodome'
            }), 500
        
        return jsonify({'error': error_message}), 500
    finally:
        session.close()

def check_pdf_is_protected(file_path):
    import PyPDF2
    """Check if a PDF file is password protected"""
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            if pdf_reader.is_encrypted:
                return True
            return False
    except Exception:
        return False 
              
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
