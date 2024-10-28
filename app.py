import os

from flask import Flask, jsonify, request
from sqlalchemy import MetaData
from flask_cors import CORS
from db_utils import connect_to_db, get_schema_info
from sqlalchemy import select
import requests

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

import json
from datetime import date, datetime

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

        # Send the data to the ingestion URL
        ingestion_url = f"https://policyengine.getpatronus.com/api/vault/vaults/{vault_name}/records/multiple"
        ingestion_response = requests.post(ingestion_url, json={"data": serialized_data})

        # Check if the ingestion request was successful
        if ingestion_response.status_code != 200:
            return jsonify({"error": "Failed to ingest data", "details": ingestion_response.text}), 500

        return jsonify({"table": table_name, "data": serialized_data, "ingestion_status": ingestion_response.json()})

    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
