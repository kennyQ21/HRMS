import os

from flask import Flask, jsonify, request
from sqlalchemy import MetaData
from flask_cors import CORS
from db_utils import connect_to_db, get_schema_info
from sqlalchemy import select
import requests
import time
from datetime import date, datetime
from sqlalchemy.exc import SQLAlchemyError



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

    if not db_type or not db_name:
        return jsonify({"error": "Missing database type or database name"}), 400

    # Connect to the database
    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        return jsonify(engine), 500

    schema_info = get_schema_info(engine)
    return jsonify(schema_info)


def serialize_data(data):
    """Recursively convert dates to strings in the data."""
    if isinstance(data, dict):
        return {key: serialize_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [serialize_data(item) for item in data]
    elif isinstance(data, (date, datetime)):
        return data.isoformat()  # Convert date/datetime to ISO 8601 string
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
    table_name = data.get("table_name")
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

    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        return jsonify(engine), 500

    try:
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

        return jsonify({"table": table_name, "data": serialized_data, "ingestion_status": ingestion_response.json()})

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
        # CORS preflight request, just return OK (200)
        return '', 200

    data = request.json
    db_type = data.get("db_type")
    db_name = data.get("db_name")
    user = data.get("user")
    password = data.get("password")
    host = data.get("host", "localhost")
    port = data.get("port", None)
    tables_info = data.get("tables_info", [])

    # Get the join key common to all tables, defaulting to 'id'
    # join_key = data.get("join_key", "id")
    join_key = "id"

    if not db_type or not db_name or not tables_info:
        return jsonify({"error": "Missing database type, database name, or table information"}), 400

    engine = connect_to_db(db_type, db_name, user, password, host, port)
    if isinstance(engine, dict) and "error" in engine:
        return jsonify(engine), 500

    try:
        metadata = MetaData()
        metadata.reflect(bind=engine)

        # Initialize the query with the first table's selected columns
        base_table_info = tables_info[0]
        base_table = metadata.tables.get(base_table_info["table_name"])

        if base_table is None:
            return jsonify({"error": f"Table '{base_table_info['table_name']}' not found"}), 404

        # Select only the specified columns for the base table
        base_columns = [
            base_table.c[col] for col in base_table_info["columns"]
            if col in base_table.c
        ] if base_table_info.get("columns") else [base_table]

        # Ensure we have columns to select
        if not base_columns:
            return jsonify({"error": f"No valid columns specified for table '{base_table_info['table_name']}'"}), 400

        query = select(*base_columns).select_from(base_table)

        # Join subsequent tables based on the common join key
        for table_info in tables_info[1:]:
            table = metadata.tables.get(table_info["table_name"])
            if table is None:
                return jsonify({"error": f"Table '{table_info['table_name']}' not found"}), 404

            # Select only the specified columns for the current table
            columns = [table.c[col] for col in table_info["columns"] if col in table.c] if table_info.get("columns") else [table]

            # Ensure we have columns to select for the current table
            if not columns:
                return jsonify({"error": f"No valid columns specified for table '{table_info['table_name']}'"}), 400

            query = query.add_columns(*columns).join(
                table,
                base_table.c[join_key] == table.c[join_key]
            )

        # Execute the query
        with engine.connect() as conn:
            result = conn.execute(query)
            rows = result.fetchall()

        # Extract raw data and serialize
        # Convert rows to a list of dicts using the _mapping property
        serialized_data = serialize_data([dict(row._mapping) for row in rows])  # Convert rows to a list of dicts

        # Send the serialized data to the ingestion URL
        ingestion_url = f"https://policyengine.getpatronus.com/api/vault/vaults/{data['vault_name']}/records/multiple"
        headers = {
            "Authorization": f"Bearer {request.headers.get('Authorization').split()[1]}",
            "Content-Type": "application/json"
        }
        ingestion_response = requests.post(ingestion_url, json={"data": serialized_data}, headers=headers)

        # Check if the ingestion request was successful
        if ingestion_response.status_code != 201:
            return jsonify({"error": "Failed to ingest data", "details": ingestion_response.text}), 500

        return jsonify({"ingestion_status": ingestion_response.json()})

    except SQLAlchemyError as e:
        return jsonify({"error": str(e)}), 500




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
