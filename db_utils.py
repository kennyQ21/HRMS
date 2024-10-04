from sqlalchemy import create_engine, inspect


def connect_to_db(db_type, db_name, user=None, password=None, host=None, port=None):
    try:
        if db_type == "postgresql":
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
            url = (
                f"mariadb+mariadbconnector://{user}:{password}@{host}:{port}/{db_name}"
            )
        else:
            raise ValueError(f"Unsupported database type: {db_type}")

        engine = create_engine(url)
        return engine
    except Exception as e:
        return {"error": f"Error connecting to the database: {e}"}


def get_schema_info(engine):
    try:
        inspector = inspect(engine)
        schema_info = {}

        # Fetch all tables from the database
        tables = inspector.get_table_names()

        # Retrieve columns for each table
        for table in tables:
            schema_info[table] = []
            columns = inspector.get_columns(table)
            for column in columns:
                schema_info[table].append(
                    {"name": column["name"], "type": str(column["type"])}
                )
        return schema_info
    except Exception as e:
        return {"error": f"Error retrieving schema information: {e}"}
