import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.pii_service import extract_pii_entities


def _entities_by_type(payload):
    grouped = {}
    for entity in payload["entities"]:
        grouped.setdefault(entity["type"], []).append(entity)
    return grouped


def test_extract_pii_entities_returns_json_serializable_regex_baseline():
    text = (
        "Name: John Mathew\n"
        "Email: john@gmail.com\n"
        "Phone: 9876543210\n"
        "PAN: ABCDE1234F\n"
        "Aadhaar: 1234 5678 9012\n"
    )

    payload = extract_pii_entities(text, use_nlp=False)
    grouped = _entities_by_type(payload)

    assert json.loads(json.dumps(payload)) == payload
    assert grouped["EMAIL"][0]["value"] == "john@gmail.com"
    assert grouped["PHONE_NUMBER"][0]["value"] == "9876543210"
    assert grouped["PAN"][0]["value"] == "ABCDE1234F"
    assert grouped["AADHAAR"][0]["value"] == "123456789012"

    for entity in payload["entities"]:
        assert set(entity) == {"type", "value", "start", "end", "score", "source"}
        assert entity["source"] == "regex"
        assert entity["score"] == 1.0


def test_extract_pii_entities_empty_text():
    assert extract_pii_entities("", use_nlp=False) == {"entities": []}
