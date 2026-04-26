from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    connector_id = Column(String, nullable=False)
    realm_name = Column(String, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    # One-to-many: Scan → ColumnScan
    column_scans = relationship(
        "ColumnScan", back_populates="scan", cascade="all, delete-orphan"
    )


class ColumnScan(Base):
    __tablename__ = "column_scans"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    db_name = Column(String, nullable=False)
    table_name = Column(String, nullable=False)
    column_name = Column(String, nullable=False)
    total_rows = Column(Integer, default=0)

    primary_pii_type = Column(String, nullable=True)
    primary_pii_match_count = Column(Integer, default=0)

    # Relationship to parent Scan
    scan = relationship("Scan", back_populates="column_scans")

    # One-to-many: ColumnScan → ScanAnomaly
    anomalies = relationship(
        "ScanAnomaly", back_populates="column_scan", cascade="all, delete-orphan"
    )

    # One-to-many: ColumnScan → PIILocation (image bbox data)
    pii_locations = relationship(
        "PIILocation", back_populates="column_scan", cascade="all, delete-orphan"
    )


class ScanAnomaly(Base):
    __tablename__ = "scan_anomalies"

    id = Column(Integer, primary_key=True)
    column_scan_id = Column(Integer, ForeignKey("column_scans.id"))
    pii_type = Column(String, nullable=False)
    match_count = Column(Integer, default=0)
    confidence_score = Column(Float)

    # Relationship with parent scan
    column_scan = relationship("ColumnScan", back_populates="anomalies")


class PIILocation(Base):
    """Bounding-box record for a single PII match found in an image."""
    __tablename__ = "pii_locations"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    column_scan_id = Column(Integer, ForeignKey("column_scans.id"), nullable=False)
    pii_type = Column(String, nullable=False)
    value = Column(String)
    # JSON-encoded polygon: [[x1,y1],[x2,y1],[x2,y2],[x1,y2]]
    bbox = Column(String, nullable=False)
    # Original filename so the redaction endpoint knows which stored image to open
    source_file = Column(String, nullable=False)

    column_scan = relationship("ColumnScan", back_populates="pii_locations")