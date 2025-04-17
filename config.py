import os

class Config:
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev')
    DEBUG = FLASK_ENV == 'development'
    
    # Database configuration
    if FLASK_ENV == 'production':
        DB_TYPE = 'postgres'
        DB_NAME = os.getenv('POSTGRES_DB', 'migration_db')
        DB_USER = os.getenv('POSTGRES_USER', 'postgres')
        DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
        DB_HOST = os.getenv('DATABASE_URL')
        DB_PORT = os.getenv('DB_PORT', '5432')
        SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        # Development environment - use SQLite
        DB_TYPE = 'sqlite'
        DB_NAME = 'pii_scans.db'
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_NAME}"
    
    # Flask-SQLAlchemy configuration
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = DEBUG 