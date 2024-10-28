from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import OperationalError

def connect_to_db(db_type, db_name, user=None, password=None, host=None, port=None):
    try:
        # Build the connection URL
        if db_type == "postgres":
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
    try:
        inspector = inspect(engine)
        schema_info = {}

        # Define PII columns with their sensitivity levels
        pii_columns = {
            "kyc": {
                "name": {"sensitivity_level": "medium"},
                "email": {"sensitivity_level": "high"},
                "pan": {"sensitivity_level": "high"},
                "aadhaar": {"sensitivity_level": "high"},
                "phone_number": {"sensitivity_level": "medium"},
            },
            "credit_card": {
                "creditcard_number": {"sensitivity_level": "high"},
                "cvv": {"sensitivity_level": "high"},
                "expiry": {"sensitivity_level": "medium"},
                "issue_date": {"sensitivity_level": "medium"},
                "kyc_id": {"sensitivity_level": "low"},
            },
        }

        # Fetch all tables from the database
        tables = inspector.get_table_names()

        # Retrieve columns for each table
        for table in tables:
            schema_info[table] = []
            columns = inspector.get_columns(table)
            for column in columns:
                is_pii = column["name"] in pii_columns.get(table, {})
                sensitivity_level = (
                    pii_columns[table][column["name"]]["sensitivity_level"] if is_pii else None
                )
                
                schema_info[table].append(
                    {
                        "name": column["name"],
                        "type": str(column["type"]),
                        "is_pii": is_pii,
                        "sensitivity_level": sensitivity_level,
                        "confidence": 0.9,  # Fixed confidence value
                    }
                )
        return schema_info
    except Exception as e:
        return {"error": f"Error retrieving schema information: {e}"}
