# Frontend Integration — Unstructured File Scanning & Redaction

Base URL: `http://<host>:5000`

All requests require a JWT in the `Authorization` header:

```
Authorization: Bearer <token>
```

The token must be HS256-signed with secret `super_secret_key` and carry the claim `"org_name": "Patronus1"`. A missing or wrong `org_name` returns `403`.

---

## Supported file types

| Type | Extensions | Scanning method |
|------|-----------|----------------|
| PDF | `.pdf` | Text layer → OCR fallback |
| Word | `.docx`, `.doc`, `.odt`, `.rtf` | Text extraction |
| Image | `.jpg`, `.jpeg`, `.png`, `.bmp`, `.tif`, `.tiff`, `.webp` | PaddleOCR |
| SQL dump | `.sql` | Text extraction |
| Access DB | `.mdb` | Table/column extraction |
| Archive | `.zip` | Each file dispatched individually |

Only image files support redaction. Other types produce scan reports only.

---

## PII type IDs

Use these string IDs in scan filters and redact requests:

| ID | Name | Sensitivity |
|----|------|------------|
| `email` | Email Address | High |
| `phone` | Phone Number | Medium |
| `dob` | Date of Birth | Medium |
| `pan` | PAN Number | High |
| `aadhaar` | Aadhaar Number | Very High |
| `credit_card` | Credit Card Number | Very High |
| `expiry` | Card Expiry Date | Low |
| `cvv` | CVV Code | Very High |
| `name` | Person Name | Medium |
| `address` | Address | Medium |
| `voter_id` | Voter ID | High |
| `ip_address` | IP Address | Low |

---

## Flow

```
POST /scan-file          →  scan_id
GET  /get-scan-results/{scan_id}  →  per-file PII report
POST /redact             →  ZIP of redacted images
```

---

## 1. POST /scan-file

Upload a file (or ZIP of files) to scan for PII.

**Request** — `multipart/form-data`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `file` | File | Yes | Any supported format or `.zip` |
| `realm_name` | string | No | Tenant identifier, stored with the scan |
| `password` | string | No | For password-protected PDFs or ZIPs |

```js
const form = new FormData();
form.append("file", fileInput.files[0]);
form.append("realm_name", "acme-corp");   // optional
// form.append("password", "secret");     // if protected

const res = await fetch("http://<host>:5000/scan-file", {
  method: "POST",
  headers: { Authorization: `Bearer ${token}` },
  body: form,
});
const data = await res.json();
```

**Success response** `200`

```json
{
  "status": "success",
  "data": {
    "scan_id": 51,
    "file_count": 3,
    "results": [
      {
        "filename": "id_card.jpg",
        "status": "success",
        "metadata": { "columns": ["content"], "rows": 1, "parser": "image_paddleocr" }
      },
      {
        "filename": "payslip.pdf",
        "status": "success",
        "metadata": { "columns": ["content"], "rows": 1, "parser": "pdf_paddleocr" }
      },
      {
        "filename": "notes.txt",
        "status": "skipped",
        "reason": "Unsupported file format"
      }
    ]
  }
}
```

**Error responses**

| Scenario | Response |
|----------|----------|
| Password-protected PDF, no password given | `{ "status": "error", "message": "PDF is password protected. Please provide a password." }` |
| Encrypted ZIP, no password given | `{ "status": "error", "message": "ZIP file is password protected. Please provide a password." }` |
| Wrong password | `{ "status": "error", "message": "Incorrect ZIP password" }` |
| Unsupported single file | `{ "status": "error", "message": "Unsupported file format" }` |

---

## 2. GET /get-scan-results/{scan_id}

Retrieve per-file PII findings for a completed scan.

```js
const res = await fetch(`http://<host>:5000/get-scan-results/${scanId}`, {
  headers: { Authorization: `Bearer ${token}` },
});
const data = await res.json();
```

**Success response** `200`

```json
{
  "status": "success",
  "data": {
    "pii_type_totals": {
      "pan": 2,
      "aadhaar": 1,
      "dob": 1
    },
    "scan_result": {
      "scan_id": 51,
      "scan_name": "File_Scan_20260426_132832",
      "connector_id": "file_upload",
      "created_at": "2026-04-26T13:28:32.783673+00:00",
      "columns": [
        {
          "id": 586,
          "db_name": "id_card.jpg",
          "table_name": "image",
          "column_name": "content",
          "total_rows": 1,
          "primary_pii_type": "pan",
          "primary_pii_match_count": 1,
          "anomalies": [
            {
              "pii_type": "aadhaar",
              "match_count": 1,
              "confidence_score": 0.019
            }
          ]
        }
      ]
    }
  }
}
```

**Key fields**

| Field | Meaning |
|-------|---------|
| `pii_type_totals` | Aggregate counts across all files — use for the summary card |
| `columns[].db_name` | The filename this row refers to |
| `columns[].primary_pii_type` | Dominant PII type detected in this file |
| `columns[].primary_pii_match_count` | How many times the primary type matched |
| `columns[].anomalies` | Secondary PII types found in the same file |

**Notes for the UI**
- `primary_pii_type` is `null` if no PII was detected in that file.
- `table_name` is `"image"` for image files, `"document"` for PDFs/Word, `"data"` for CSV/Excel.
- A file appears as one entry in `columns` regardless of page/sheet count.

---

## 3. POST /redact

Redact selected PII types from previously scanned images and download a ZIP of the results.

Only files that were scanned as **images** (`.jpg`, `.jpeg`, `.png`, `.bmp`, `.tif`, `.tiff`, `.webp`) can be redacted. Redaction draws black rectangles over every detected PII region using the bounding boxes stored during the scan.

**Request** — `application/json`

```json
{
  "scan_id": 51,
  "filenames": ["id_card_front.jpg", "id_card_back.jpg"],
  "pii_types": ["pan", "aadhaar", "dob"]
}
```

| Field | Type | Notes |
|-------|------|-------|
| `scan_id` | int | From `/scan-file` response |
| `filenames` | string[] | Exact filenames as returned in `scan_result.columns[].db_name` |
| `pii_types` | string[] | PII type IDs to redact; use the list from the PII type IDs table above |

```js
const res = await fetch("http://<host>:5000/redact", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    scan_id: 51,
    filenames: ["id_card.jpg"],
    pii_types: ["pan", "aadhaar"],
  }),
});

// Response is a ZIP binary stream
const blob = await res.blob();
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url;
a.download = `redacted_scan_${scanId}.zip`;
a.click();
```

**Success response** `200` — binary ZIP stream

```
Content-Type: application/zip
Content-Disposition: attachment; filename="redacted_scan_51.zip"
```

The ZIP contains one file per requested image, prefixed with `redacted_`:

```
redacted_id_card.jpg
redacted_id_card_back.jpg
```

**Error responses**

| HTTP | Scenario |
|------|----------|
| `404` | No bounding-box data found — file was not scanned as an image, or scan_id/filenames don't match |
| `500` | Stored image files missing (e.g. server restarted and `uploads/` was not persisted) |
| `401` | Missing or expired JWT |
| `403` | `org_name` claim is not `Patronus1` |

---

## End-to-end example (React pseudocode)

```jsx
// Step 1 — upload and scan
const formData = new FormData();
formData.append("file", zipFile);
formData.append("realm_name", orgId);

const { data: scanData } = await api.post("/scan-file", formData);
const scanId = scanData.scan_id;

// Step 2 — show results
const { data: results } = await api.get(`/get-scan-results/${scanId}`);
const imageFiles = results.scan_result.columns
  .filter(c => c.primary_pii_type !== null)
  .map(c => c.db_name);

// Step 3 — let user pick PII types and redact
const redactRes = await fetch("/redact", {
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
  body: JSON.stringify({
    scan_id: scanId,
    filenames: imageFiles,
    pii_types: ["pan", "aadhaar", "dob"],
  }),
});
const zipBlob = await redactRes.blob();
// offer download or display previews
```

---

## Things to know

- **Scan is async-safe** — `/scan-file` runs OCR in a thread pool. For large ZIPs or many-page PDFs, expect 10–60 s. Keep the connection open; don't poll.
- **Redaction is non-destructive** — the original image is kept at `uploads/<scan_id>/<filename>` on the server. `/redact` always produces a new copy; calling it twice is safe.
- **Bboxes are stored per OCR line** — if the same Aadhaar number appears on both front and back of a card (two separate lines), both regions are independently redacted.
- **Non-image files cannot be redacted** — PDFs and Word documents produce scan results but no bounding-box data. Redaction for those formats is not supported.
- **GET /get-scans** — lists all scans, optionally filtered by `?realm_name=acme-corp`. Useful for building a scan history view.
