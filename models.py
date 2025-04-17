from datetime import datetime, timezone
from extensions import db

class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    connector_id = db.Column(db.String, nullable=False)
    realm_name = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # One-to-many: Scan → ColumnScan
    column_scans = db.relationship("ColumnScan", back_populates="scan", cascade="all, delete-orphan")


class ColumnScan(db.Model):
    __tablename__ = 'column_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))  
    db_name = db.Column(db.String, nullable=False)
    table_name = db.Column(db.String, nullable=False)
    column_name = db.Column(db.String, nullable=False)
    total_rows = db.Column(db.Integer, default=0)
    
    primary_pii_type = db.Column(db.String, nullable=True)
    primary_pii_match_count = db.Column(db.Integer, default=0)

    # Relationship to parent Scan
    scan = db.relationship("Scan", back_populates="column_scans")

    # One-to-many: ColumnScan → ScanAnomaly
    anomalies = db.relationship("ScanAnomaly", back_populates="column_scan", cascade="all, delete-orphan")


class ScanAnomaly(db.Model):
    __tablename__ = 'scan_anomalies'
    
    id = db.Column(db.Integer, primary_key=True)
    column_scan_id = db.Column(db.Integer, db.ForeignKey('column_scans.id'))
    pii_type = db.Column(db.String, nullable=False)
    match_count = db.Column(db.Integer, default=0)
    confidence_score = db.Column(db.Float)
    
    # Relationship with parent scan
    column_scan = db.relationship("ColumnScan", back_populates="anomalies")