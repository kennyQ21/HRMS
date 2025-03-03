import os
from flask import Flask, jsonify, request
from sqlalchemy import MetaData
from flask_cors import CORS
from db_utils import connect_to_db, scan_columns_for_pii_sql, scan_columns_for_pii_mongo
from sqlalchemy import select, text
import requests
import time
from datetime import date, datetime
from sqlalchemy.exc import SQLAlchemyError
import uuid
from bson.objectid import ObjectId


app = Flask(__name__)
CORS(app)
app.config["DEBUG"] = os.getenv("FLASK_ENV") == "development"


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
    if db_type=="postgres":
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



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
