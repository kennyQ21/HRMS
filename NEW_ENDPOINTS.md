# New / Updated Endpoints

## Updated

### GET /get-scans

Returns a flat list of all scans (optionally filtered by realm).

**Query params**

| Param | Type | Required |
|-------|------|----------|
| `realm_name` | string | No |

**Response**

```json
{
  "total": 14,
  "scans": [
    {
      "id": 68,
      "name": "File_Scan_20260427_043748",
      "connector_id": "file_upload",
      "realm_name": "Patronus1",
      "created_at": "2026-04-27T04:37:48.830145+00:00",
      "column_count": 5
    }
  ]
}
```

> Previously returned `{ status, data: { scans, total } }` — now flat.

---

## New

### POST /scan/start/

Queue a scan for a connector.

**Request body**

```json
{
  "connector_id": "drive_connector",
  "realm_name": "Patronus1"
}
```

| Field | Type | Required |
|-------|------|----------|
| `connector_id` | string | Yes |
| `realm_name` | string | No |

**Response**

```json
{
  "scan_id": 69,
  "status": "queued",
  "message": "Scan started"
}
```

---

### GET /scan/scans/{scan_id}/

Poll the status of a scan.

**Path param:** `scan_id` — integer scan ID

**Response**

```json
{
  "id": 69,
  "status": "completed",
  "started_at": "2026-04-27T05:16:47.000000+00:00",
  "completed_at": "2026-04-27T05:16:47.000000+00:00"
}
```

**Status values**

| Value | Meaning |
|-------|---------|
| `queued` | Scan created, no results yet |
| `scanning` | Created < 5 minutes ago, no results yet |
| `completed` | Has scan results |
| `failed` | Created > 5 minutes ago, still no results |

---

### GET /scan/files/

File tree with PII detections for a given connector, grouped by scan.

**Query params**

| Param | Type | Required |
|-------|------|----------|
| `connector_id` | string | Yes |

**Response**

```json
[
  {
    "name": "File_Scan_20260427_043748",
    "type": "folder",
    "children": [
      {
        "name": "invoice.jpg",
        "type": "file",
        "detections": [
          { "type": "aadhaar", "confidence": 1.0 },
          { "type": "pan", "confidence": 0.9 }
        ]
      }
    ]
  }
]
```

---

### GET /data-discovery/dashboard/summary

Aggregated KPI summary across all scans for the dashboard.

**Query params**

| Param | Type | Required |
|-------|------|----------|
| `realm_name` | string | No |
| `from_date` | ISO-8601 string | No |
| `to_date` | ISO-8601 string | No |

**Response**

```json
{
  "generated_at": "2026-04-27T05:16:47.753970+00:00",
  "realm_name": "Patronus1",
  "window": {
    "from": "2026-04-01T00:00:00Z",
    "to": "2026-04-27T23:59:59Z"
  },
  "scan_counts": {
    "all": 14,
    "structured": 1,
    "unstructured": 13
  },
  "status_counts": {
    "queued": 7,
    "scanning": 0,
    "completed": 7,
    "failed": 0
  },
  "findings": {
    "flagged_assets": {
      "all": 3,
      "structured_columns": 1,
      "unstructured_files": 2
    },
    "pii_matches": {
      "all": 659,
      "structured": 643,
      "unstructured": 16
    },
    "unique_pii_types": {
      "all": 3,
      "structured": 2,
      "unstructured": 3
    },
    "high_risk": {
      "all": 2,
      "structured_anomalies": 0,
      "unstructured_files": 2
    },
    "redaction_eligible_files": 8
  },
  "top_pii_types": [
    { "type": "email", "count": 504 },
    { "type": "phone", "count": 153 },
    { "type": "credit_card", "count": 2 }
  ],
  "recent_scans": [
    {
      "scan_id": 68,
      "scan_name": "File_Scan_20260427_043748",
      "mode": "unstructured",
      "status": "completed",
      "created_at": "2026-04-27T04:37:48.830145+00:00",
      "flagged_assets": 0,
      "pii_matches": 0
    }
  ]
}
```

**Notes**
- `high_risk` counts columns/files where the primary PII type is one of: `aadhaar`, `pan`, `credit_card`, `cvv`, `in_pan`, `in_aadhaar`, `in_voter`, `voter_id`
- `redaction_eligible_files` counts image-backed column scans (`table_name == "image"`)
- `mode` in `recent_scans` is `"unstructured"` when `connector_id == "file_upload"`, otherwise `"structured"`
- Status is derived from scan results — no separate status field in the database
