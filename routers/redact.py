"""
Router: image redaction

Endpoint:
  POST /redact  – draw black rectangles over selected PII types in stored images
                  and return a ZIP of the redacted files
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from config import UPLOADS_DIR
from database import get_db
from models import PIILocation
from schemas import RedactRequest

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Redaction"])


def _redact_image(img_path: str, locations: list[PIILocation]) -> bytes:
    """
    Open the image at *img_path*, paint a black filled rectangle over every
    bounding box in *locations*, and return the result as raw image bytes.

    bbox is stored as a JSON-encoded polygon [[x1,y1],[x2,y1],[x2,y2],[x1,y2]].
    We compute the axis-aligned bounding rectangle (min/max of the polygon
    points) because PIL's rectangle fill is simpler and robust enough for
    typical OCR quads that are nearly axis-aligned.
    """
    from PIL import Image, ImageDraw

    img = Image.open(img_path).convert("RGB")
    draw = ImageDraw.Draw(img)

    for loc in locations:
        try:
            poly = json.loads(loc.bbox)
            xs = [p[0] for p in poly]
            ys = [p[1] for p in poly]
            draw.rectangle([min(xs), min(ys), max(xs), max(ys)], fill="black")
        except Exception:
            logger.warning("Skipping malformed bbox for pii_location id=%s", loc.id)

    buf = io.BytesIO()
    ext = img_path.rsplit(".", 1)[-1].lower()
    fmt = "JPEG" if ext in ("jpg", "jpeg") else ext.upper()
    try:
        img.save(buf, format=fmt)
    except Exception:
        img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


@router.post("/redact")
async def redact_images(body: RedactRequest, db: Session = Depends(get_db)):
    """
    Redact selected PII types from previously scanned images.

    Reads bounding boxes stored during /scan-file, paints black rectangles
    over matching regions in the stored originals, and returns a ZIP archive
    of the redacted images.

    Request body:
        scan_id   – ID returned by /scan-file
        filenames – which image files within that scan to redact
        pii_types – which PII type IDs to redact (e.g. ["pan", "aadhaar"])
    """
    locations = (
        db.query(PIILocation)
        .filter(
            PIILocation.scan_id == body.scan_id,
            PIILocation.source_file.in_(body.filenames),
            PIILocation.pii_type.in_(body.pii_types),
        )
        .all()
    )

    if not locations:
        raise HTTPException(
            status_code=404,
            detail=(
                "No bounding-box data found for the given scan_id / filenames / pii_types. "
                "Only images scanned via /scan-file support redaction."
            ),
        )

    # Group locations by source file
    by_file: dict[str, list[PIILocation]] = defaultdict(list)
    for loc in locations:
        by_file[loc.source_file].append(loc)

    zip_buf = io.BytesIO()
    redacted_count = 0

    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, file_locs in by_file.items():
            img_path = UPLOADS_DIR / str(body.scan_id) / filename
            if not img_path.exists():
                logger.warning(
                    "Stored image not found: %s — skipping (was it scanned with an older version?)",
                    img_path,
                )
                continue

            try:
                redacted_bytes = _redact_image(str(img_path), file_locs)
                zf.writestr(f"redacted_{filename}", redacted_bytes)
                redacted_count += 1
                logger.info(
                    "Redacted %d region(s) in %s", len(file_locs), filename
                )
            except Exception as exc:
                logger.error("Failed to redact %s: %s", filename, exc)

    if redacted_count == 0:
        raise HTTPException(
            status_code=500,
            detail="Redaction failed: stored image files could not be found or processed.",
        )

    zip_buf.seek(0)
    return StreamingResponse(
        zip_buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="redacted_scan_{body.scan_id}.zip"'
        },
    )
