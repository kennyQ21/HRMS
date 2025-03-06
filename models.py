from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class ColumnScan(Base):
    __tablename__ = 'column_scans'
    
    id = Column(Integer, primary_key=True)
    connector_id = Column(String, nullable=False)
    db_name = Column(String, nullable=False)
    table_name = Column(String, nullable=False)
    column_name = Column(String, nullable=False)
    scan_date = Column(DateTime, default=datetime.datetime.utcnow)
    total_rows = Column(Integer, default=0)
    
    # Store the detected PII type (if any)
    primary_pii_type = Column(String, nullable=True)
    primary_pii_match_count = Column(Integer, default=0)
    
    # Relationship with anomalies
    anomalies = relationship("ScanAnomaly", back_populates="column_scan")

class ScanAnomaly(Base):
    __tablename__ = 'scan_anomalies'
    
    id = Column(Integer, primary_key=True)
    column_scan_id = Column(Integer, ForeignKey('column_scans.id'))
    pii_type = Column(String, nullable=False)
    match_count = Column(Integer, default=0)
    confidence_score = Column(Float)
    
    # Relationship with parent scan
    column_scan = relationship("ColumnScan", back_populates="anomalies")

# Create SQLite database
engine = create_engine('sqlite:///pii_scans.db')
Base.metadata.create_all(engine) 