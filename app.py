from flask import Flask, request, jsonify
from db_utils import connect_to_db, get_schema_info
import os 


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
