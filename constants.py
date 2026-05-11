from typing import TypedDict
from enum import Enum


class Category(str, Enum):
    GOVERNMENT_ID  = "Government ID"
    FINANCIAL      = "Financial"
    AUTHENTICATION = "Authentication"
    PERSONAL       = "Personal"
    MEDICAL        = "Medical"
    INSURANCE      = "Insurance"
    DEMOGRAPHIC    = "Demographic"
    EMPLOYMENT     = "Employment"
    EDUCATIONAL    = "Educational"
    CONTACT        = "Contact"
    GEO            = "Geo"
    OTHER          = "Other"


class Sensitivity(str, Enum):
    CRITICAL  = "Critical"
    VERY_HIGH = "Very High"
    HIGH      = "High"
    MEDIUM    = "Medium"
    LOW       = "Low"


class PIIType(TypedDict):
    id:          str
    name:        str
    description: str
    category:    Category
    sensitivity: Sensitivity
    regex:       str


# ── MASTER PII Types ──────────────────────────────────────────────────────────
# Covers all detection categories: deterministic (regex), semantic (GLiNER/LLM),
# structural (Otter), and contextual.
#
# Each entry needs an id and sensitivity for routing; regex may be empty ("") for
# types detected only by NER/LLM engines.

PII_TYPES: list[PIIType] = [

    # ── Government IDs ───────────────────────────────────────────────────────
    {
        "id":          "aadhaar",
        "name":        "Aadhaar Number",
        "description": "12-digit Indian national biometric ID",
        "category":    Category.GOVERNMENT_ID,
        "sensitivity": Sensitivity.VERY_HIGH,
        "regex":       r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)",
    },
    {
        "id":          "pan",
        "name":        "PAN Number",
        "description": "Indian Permanent Account Number",
        "category":    Category.GOVERNMENT_ID,
        "sensitivity": Sensitivity.HIGH,
        "regex":       r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    },
    {
        "id":          "passport",
        "name":        "Passport Number",
        "description": "International travel document number",
        "category":    Category.GOVERNMENT_ID,
        "sensitivity": Sensitivity.VERY_HIGH,
        # Requires explicit label to avoid colliding with PAN/voter IDs.
        # Covers: India (A1234567), US (123456789), UK (123456789), EU formats.
        "regex":       r"(?i)\b(?:passport\s*(?:no|num(?:ber)?|#)?)\s*[:\-]?\s*([A-Z0-9]{6,9})\b",
    },
    {
        "id":          "voter_id",
        "name":        "Voter ID",
        "description": "Indian Electoral Photo Identity Card (EPIC)",
        "category":    Category.GOVERNMENT_ID,
        "sensitivity": Sensitivity.HIGH,
        "regex":       r"\b[A-Z]{3}[0-9]{7}\b",
    },
    {
        "id":          "driving_license",
        "name":        "Driving Licence",
        "description": "Indian state-issued driving licence number",
        "category":    Category.GOVERNMENT_ID,
        "sensitivity": Sensitivity.HIGH,
        "regex":       r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,15}\b",
    },
    {
        "id":          "ssn",
        "name":        "Social Security Number",
        "description": "US Social Security Number",
        "category":    Category.GOVERNMENT_ID,
        "sensitivity": Sensitivity.VERY_HIGH,
        "regex":       r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    },

    # ── Financial ────────────────────────────────────────────────────────────
    {
        "id":          "credit_card",
        "name":        "Credit/Debit Card Number",
        "description": "16-digit payment card number (Luhn-validated)",
        "category":    Category.FINANCIAL,
        "sensitivity": Sensitivity.HIGH,
        "regex":       r"\b(?:\d[ -]*?){13,16}\b",
    },
    {
        "id":          "bank_account",
        "name":        "Bank Account Number",
        "description": "Bank account number",
        "category":    Category.FINANCIAL,
        "sensitivity": Sensitivity.VERY_HIGH,
        "regex":       r"(?i)\b(?:account\s*(?:no|num(?:ber)?|#)\s*[:\-]?\s*)([0-9]{9,18})\b",
    },
    {
        "id":          "upi",
        "name":        "UPI ID",
        "description": "Unified Payments Interface virtual address",
        "category":    Category.FINANCIAL,
        "sensitivity": Sensitivity.HIGH,
        # UPI IDs end with known bank VPA handles — explicitly match those,
        # not generic email-like @domain patterns.
        "regex":       r"\b[a-zA-Z0-9.\-_]{2,}@(?:okaxis|okhdfcbank|oksbi|okicici|ybl|axisbank|upi|paytm|ibl|timecosmos|apl|jupiter|fbl|rbl|kotak|barodampay|centralbank|idbi|pnb|aubank|indus|mahb|scb|abfspay|nsdl|juspay)\b",
    },
    {
        "id":          "ifsc",
        "name":        "IFSC Code",
        "description": "Indian Financial System Code for bank branches",
        "category":    Category.FINANCIAL,
        "sensitivity": Sensitivity.MEDIUM,
        "regex":       r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    },
    {
        "id":          "iban",
        "name":        "IBAN",
        "description": "International Bank Account Number (EU/global)",
        "category":    Category.FINANCIAL,
        "sensitivity": Sensitivity.VERY_HIGH,
        # Matches IBAN: GB29 NWBK 6016 1331 9268 19, DE89370400440532013000, etc.
        "regex":       r"\b[A-Z]{2}\d{2}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4}\b",
    },
    {
        "id":          "nhs_number",
        "name":        "NHS Number",
        "description": "UK National Health Service patient number",
        "category":    Category.GOVERNMENT_ID,
        "sensitivity": Sensitivity.VERY_HIGH,
        "regex":       r"(?i)\b(?:nhs\s*(?:no|num(?:ber)?|#)?)\s*[:\-]?\s*(\d{3}[\s\-]?\d{3}[\s\-]?\d{4})\b",
    },
    {
        "id":          "expiry",
        "name":        "Card Expiry Date",
        "description": "Payment card expiry date",
        "category":    Category.FINANCIAL,
        "sensitivity": Sensitivity.MEDIUM,
        "regex":       r"(?i)\b(?:exp(?:iry)?|valid\s*(?:thru|through|till))\s*[:\-]?\s*(?:0[1-9]|1[0-2])[\/\-]\d{2,4}\b",
    },
    {
        "id":          "cvv",
        "name":        "CVV / CVC",
        "description": "Card verification value",
        "category":    Category.FINANCIAL,
        "sensitivity": Sensitivity.CRITICAL,
        "regex":       r"(?i)\b(?:cvv|cvc|security\s*code)\s*[:\-]?\s*\d{3,4}\b",
    },

    # ── Authentication ────────────────────────────────────────────────────────
    {
        "id":          "user_id",
        "name":        "Username / User ID",
        "description": "System login identifier",
        "category":    Category.AUTHENTICATION,
        "sensitivity": Sensitivity.MEDIUM,
        "regex":       r"(?i)\b(?:username|user(?:\s*id)?|login(?:\s*id)?)\s*[:\-]?\s*([A-Za-z0-9._@\-]{3,50})",
    },
    {
        "id":          "password",
        "name":        "Password",
        "description": "Authentication credential",
        "category":    Category.AUTHENTICATION,
        "sensitivity": Sensitivity.CRITICAL,
        "regex":       r"(?i)\b(?:password|passwd|pwd)\s*[:\-=]?\s*(\S{6,})",
    },

    # ── Personal ──────────────────────────────────────────────────────────────
    {
        "id":          "name",
        "name":        "Person Name",
        "description": "Full or partial person name",
        "category":    Category.PERSONAL,
        "sensitivity": Sensitivity.MEDIUM,
        "regex":       "",   # detected by GLiNER / Presidio
    },
    {
        "id":          "dob",
        "name":        "Date of Birth",
        "description": "Birth date",
        "category":    Category.PERSONAL,
        "sensitivity": Sensitivity.HIGH,
        # Universal DOB: label-gated to avoid false positives on bare dates.
        # Matches: DD/MM/YYYY, MM-DD-YYYY, YYYY.MM.DD, and label variants in any language context.
        "regex":       r"(?i)\b(?:dob|date\s*of\s*birth|birth\s*(?:date|day)|born\s*(?:on)?|जन्म\s*तिथि|تاريخ الميلاد)\s*[:\-]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b",
    },
    {
        "id":          "address",
        "name":        "Physical Address",
        "description": "Full or partial postal address",
        "category":    Category.PERSONAL,
        "sensitivity": Sensitivity.MEDIUM,
        "regex":       r"(?i)\b(?:address|addr)\s*[:\-]?\s*[A-Za-z0-9][A-Za-z0-9\s,./#\-]{8,}",
    },
    {
        "id":          "gender",
        "name":        "Gender",
        "description": "Gender or sex identification",
        "category":    Category.DEMOGRAPHIC,
        "sensitivity": Sensitivity.LOW,
        "regex":       r"(?i)\b(?:gender|sex)\s*[:\-]?\s*(?:male|female|non[\s\-]binary|transgender|other)\b",
    },
    {
        "id":          "age",
        "name":        "Age",
        "description": "Person age",
        "category":    Category.DEMOGRAPHIC,
        "sensitivity": Sensitivity.LOW,
        "regex":       r"(?i)\b(?:age)\s*[:\-]?\s*(\d{1,3})\s*(?:years?|yrs?)?\b",
    },
    {
        "id":          "nationality",
        "name":        "Nationality",
        "description": "Nationality or citizenship",
        "category":    Category.PERSONAL,
        "sensitivity": Sensitivity.LOW,
        "regex":       "",   # detected by GLiNER / LLM
    },
    {
        "id":          "marital_status",
        "name":        "Marital Status",
        "description": "Marital or relationship status",
        "category":    Category.DEMOGRAPHIC,
        "sensitivity": Sensitivity.LOW,
        "regex":       r"(?i)\b(?:marital\s*status)\s*[:\-]?\s*(?:single|married|divorced|widowed|separated|unmarried)\b",
    },

    # ── Medical ───────────────────────────────────────────────────────────────
    {
        "id":          "diagnosis",
        "name":        "Medical Diagnosis",
        "description": "Medical condition or diagnosis",
        "category":    Category.MEDICAL,
        "sensitivity": Sensitivity.CRITICAL,
        "regex":       "",   # semantic — detected by Qwen LLM + GLiNER
    },
    {
        "id":          "allergies",
        "name":        "Allergies",
        "description": "Drug or environmental allergy records",
        "category":    Category.MEDICAL,
        "sensitivity": Sensitivity.CRITICAL,
        # Line-bounded so it doesn't greedily consume following lines
        "regex":       r"(?i)\b(?:allerg(?:y|ies|ic\s*to))\s*[:\-]?\s*([A-Za-z][A-Za-z,\s]{2,50})(?=\n|$|;|\|)",
    },
    {
        "id":          "treatment_history",
        "name":        "Treatment History",
        "description": "Medical procedures or treatment records",
        "category":    Category.MEDICAL,
        "sensitivity": Sensitivity.CRITICAL,
        "regex":       "",   # semantic — detected by Qwen LLM
    },
    {
        "id":          "prescription",
        "name":        "Prescription / Medication",
        "description": "Drug prescriptions or dosage information",
        "category":    Category.MEDICAL,
        "sensitivity": Sensitivity.CRITICAL,
        "regex":       r"(?i)\b(?:prescribed?|medication|tablet|capsule|mg\s*/\s*(?:day|dose))\b",
    },
    {
        "id":          "immunization",
        "name":        "Immunization Record",
        "description": "Vaccination or immunization history",
        "category":    Category.MEDICAL,
        "sensitivity": Sensitivity.HIGH,
        "regex":       r"(?i)\b(?:vaccin(?:e|ated|ation)|immuniz(?:ed|ation)|booster)\b",
    },
    {
        "id":          "blood_group",
        "name":        "Blood Group",
        "description": "ABO and Rh blood type",
        "category":    Category.MEDICAL,
        "sensitivity": Sensitivity.MEDIUM,
        "regex":       r"\b(?:A|B|AB|O)[+-]\b",
    },
    {
        "id":          "mrn",
        "name":        "Medical Record Number",
        "description": "Hospital or clinic patient MRN",
        "category":    Category.MEDICAL,
        "sensitivity": Sensitivity.VERY_HIGH,
        "regex":       r"(?i)\b(?:mrn|patient\s*id|record\s*(?:no|num(?:ber)?))\s*[:\-#]?\s*([A-Z0-9]{4,15})\b",
    },

    # ── Insurance ─────────────────────────────────────────────────────────────
    {
        "id":          "insurance_policy",
        "name":        "Insurance Policy Number",
        "description": "Health, life, or general insurance policy ID",
        "category":    Category.INSURANCE,
        "sensitivity": Sensitivity.HIGH,
        "regex":       r"(?i)\b(?:policy\s*(?:no|num(?:ber)?|#))\s*[:\-]?\s*([A-Z0-9/\-]{5,20})\b",
    },
    {
        "id":          "insurance_provider",
        "name":        "Insurance Provider",
        "description": "Name of insurance company",
        "category":    Category.INSURANCE,
        "sensitivity": Sensitivity.LOW,
        "regex":       "",   # detected by GLiNER / LLM
    },

    # ── Employment ────────────────────────────────────────────────────────────
    {
        "id":          "occupation",
        "name":        "Occupation / Job Title",
        "description": "Profession, designation, or job role",
        "category":    Category.EMPLOYMENT,
        "sensitivity": Sensitivity.LOW,
        "regex":       "",   # semantic — detected by GLiNER / Qwen
    },
    {
        "id":          "employee_id",
        "name":        "Employee ID",
        "description": "Internal employee or staff identifier",
        "category":    Category.EMPLOYMENT,
        "sensitivity": Sensitivity.MEDIUM,
        "regex":       r"(?i)\b(?:emp(?:loyee)?\s*(?:id|no|code))\s*[:\-#]?\s*([A-Z0-9]{3,15})\b",
    },
    {
        "id":          "corporate_email",
        "name":        "Corporate Email",
        "description": "Work or organisation email address (non-consumer domain)",
        "category":    Category.EMPLOYMENT,
        "sensitivity": Sensitivity.MEDIUM,
        # Only match non-consumer domains; consumer domains handled by 'email' type
        "regex":       r"[A-Za-z0-9._%+\-]+@(?!(?:gmail|yahoo|hotmail|outlook|rediff|icloud|proton)\.)[A-Za-z0-9\-]+\.(?:com|org|net|in|co\.in|gov\.in)",
    },
    {
        "id":          "organization",
        "name":        "Organisation Name",
        "description": "Company, institution, or agency name",
        "category":    Category.EMPLOYMENT,
        "sensitivity": Sensitivity.LOW,
        "regex":       "",   # detected by GLiNER / Presidio
    },

    # ── Educational ───────────────────────────────────────────────────────────
    {
        "id":          "educational_qualification",
        "name":        "Educational Qualification",
        "description": "Academic degrees, diplomas, or certifications",
        "category":    Category.EDUCATIONAL,
        "sensitivity": Sensitivity.LOW,
        # Requires explicit degree abbreviations (B.Tech, BSc, MBA, PhD, etc.)
        # or full words (Bachelor, Master, Doctorate, Diploma).
        # Old pattern matched "be"/"me"/"ba"/"ma" as single letters — fixed.
        "regex":       r"\b(?:B\.(?:Sc|Tech|E|Com|A|Ed)|BSc|BTech|BE|BEd|BCom|BA|"
                       r"M\.(?:Sc|Tech|E|Com|B\.A|Ed|Phil)|MSc|MTech|ME|MBA|MEd|MPhil|"
                       r"M\.D\.|Ph\.D\.?|PhD|MBBS|M\.B\.B\.S|"
                       r"[Dd]iploma|[Bb]achelor(?:'?s)?|[Mm]aster(?:'?s)?|[Dd]octorate|"
                       r"[Pp]ost[Gg]raduate|[Uu]ndergraduate)\b",
    },

    # ── Contact ───────────────────────────────────────────────────────────────
    {
        "id":          "email",
        "name":        "Email Address",
        "description": "Personal or professional email address",
        "category":    Category.CONTACT,
        "sensitivity": Sensitivity.HIGH,
        "regex":       r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    },
    {
        "id":          "phone",
        "name":        "Phone Number",
        "description": "Mobile, landline, or international phone number in any country",
        "category":    Category.CONTACT,
        "sensitivity": Sensitivity.MEDIUM,
        # Universal phone — two patterns to avoid false positives:
        # 1. International format: must start with + and country code
        # 2. Label-gated local: requires phone/mobile/tel label
        # This prevents 12-digit Aadhaar numbers being matched as phones.
        "regex":       r"(?:"
                       r"\+\d{1,3}[\s\-.]?(?:\(0?\d{1,4}\)[\s\-.]?)?\d{3,5}[\s\-.]?\d{3,5}(?:[\s\-.]?\d{2,5})?"
                       r"|(?i)(?:phone|mobile|tel|ph|mob|contact)\s*[:\-]?\s*(?:\+\d{1,3}[\s\-.]?)?\d{3,5}[\s\-.]?\d{3,5}(?:[\s\-.]?\d{2,5})?"
                       r")(?!\d)",
    },

    # ── Geo ───────────────────────────────────────────────────────────────────
    {
        "id":          "pincode",
        "name":        "Postal / PIN Code",
        "description": "6-digit Indian PIN code",
        "category":    Category.GEO,
        "sensitivity": Sensitivity.LOW,
        # 6-digit Indian PIN codes only; require context label to reduce false positives
        "regex":       r"(?i)\b(?:pin\s*(?:code)?|postal\s*(?:code)?|zip)\s*[:\-]?\s*(\d{6})\b",
    },
    {
        "id":          "city",
        "name":        "City / Town",
        "description": "City, town, or locality name",
        "category":    Category.GEO,
        "sensitivity": Sensitivity.LOW,
        "regex":       "",   # detected by GLiNER / Presidio LOCATION
    },

    # ── Medication (detected by LLM + post-processor drug canonicalization) ─────
    {
        "id":          "medication",
        "name":        "Medication / Drug Name",
        "description": "Specific pharmaceutical drug or brand-name medication",
        "category":    Category.MEDICAL,
        "sensitivity": Sensitivity.HIGH,
        "regex":       "",   # detected by LLM and post-processor drug ontology
    },

    # ── Other ─────────────────────────────────────────────────────────────────
    {
        "id":          "ip_address",
        "name":        "IP Address",
        "description": "IPv4 or IPv6 network address",
        "category":    Category.OTHER,
        "sensitivity": Sensitivity.MEDIUM,
        "regex":       r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    },
]


# Convenience lookup: id → PII entry
PII_TYPE_MAP: dict[str, PIIType] = {p["id"]: p for p in PII_TYPES}

# Sensitivity ordering (highest first) — used for priority scoring
SENSITIVITY_ORDER: dict[str, int] = {
    Sensitivity.CRITICAL:  6,
    Sensitivity.VERY_HIGH: 5,
    Sensitivity.HIGH:      4,
    Sensitivity.MEDIUM:    3,
    Sensitivity.LOW:       2,
}

# IDs whose detection is purely semantic (no regex) — routed to NER/LLM only
SEMANTIC_ONLY_PII: set[str] = {
    p["id"] for p in PII_TYPES if not p.get("regex")
}

# IDs that benefit most from LLM interpretation
LLM_PRIORITY_PII: set[str] = {
    "diagnosis", "treatment_history", "allergies", "prescription",
    "immunization", "occupation", "educational_qualification",
    "insurance_provider", "nationality",
}
