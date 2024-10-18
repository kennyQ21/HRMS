import os

from flask import Flask, jsonify, request
from sqlalchemy import MetaData

from db_utils import connect_to_db, get_schema_info

app = Flask(__name__)
app.config["DEBUG"] = os.getenv("FLASK_ENV") == "development"


@app.route("/get-schema", methods=["POST"])
def get_schema():
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

    if not db_type or not db_name or not table_name:
        return (
            jsonify({"error": "Missing database type, database name, or table name"}),
            400,
        )

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
        query = table.select()
        result = conn.execute(query)
        rows = result.fetchall()

        # Convert rows to a list of dictionaries
        column_names = table.columns.keys()  
        table_data = [dict(zip(column_names, row)) for row in rows]

        conn.close()

        return jsonify({"table": table_name, "data": table_data})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
