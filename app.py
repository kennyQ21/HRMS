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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
