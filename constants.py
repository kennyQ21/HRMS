from typing import TypedDict
from enum import Enum

class Category(str, Enum):
    PERSONAL = 'Personal'
    FINANCIAL = 'Financial'
    HEALTHCARE = 'Healthcare'
    PROFESSIONAL = 'Professional'
    OTHER = 'Other'

class Sensitivity(str, Enum):
    VERY_HIGH = 'Very High'
    HIGH = 'High'
    MEDIUM = 'Medium'
    LOW = 'Low'

class PIIType(TypedDict):
    id: str
    name: str
    description: str
    category: Category
    sensitivity: Sensitivity
    regex: str

PII_TYPES: list[PIIType] = [
    {
        'id': 'email',
        'name': 'Email Address',
        'description': 'Personal or professional email addresses',
        'category': Category.PERSONAL,
        'sensitivity': Sensitivity.HIGH,
        'regex': r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    },
    {
        'id': 'phone',
        'name': 'Phone Number', 
        'description': 'Mobile, landline, or fax numbers',
        'category': Category.PERSONAL,
        'sensitivity': Sensitivity.MEDIUM,
        'regex': r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    },
    {
        'id': 'dob',
        'name': 'Date of Birth',
        'description': 'Birth date information',
        'category': Category.PERSONAL,
        'sensitivity': Sensitivity.MEDIUM,
        'regex': r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b"
    },
    {
        'id': 'pan',
        'name': 'PAN Number',
        'description': 'Permanent Account Number',
        'category': Category.FINANCIAL,
        'sensitivity': Sensitivity.HIGH,
        'regex': r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
    },
    {
        'id': 'aadhaar',
        'name': 'Aadhaar Number',
        'description': 'Unique identification number',
        'category': Category.PERSONAL,
        'sensitivity': Sensitivity.HIGH,
        'regex': r"\b\d{4}\s?\d{4}\s?\d{4}\b"
    },
    {
        'id': 'credit_card',
        'name': 'Credit Card Number',
        'description': 'Credit card numbers',
        'category': Category.FINANCIAL,
        'sensitivity': Sensitivity.HIGH,
        'regex': r"\b(?:\d[ -]*?){13,16}\b"
    },
    {
        'id': 'expiry',
        'name': 'Expiry Date',
        'description': 'Card expiry dates',
        'category': Category.FINANCIAL,
        'sensitivity': Sensitivity.MEDIUM,
        'regex': r"\b(0[1-9]|1[0-2])[/\-](\d{2}|\d{4})\b"
    },
    {
        'id': 'cvv',
        'name': 'CVV',
        'description': 'Card verification value',
        'category': Category.FINANCIAL,
        'sensitivity': Sensitivity.HIGH,
        'regex': r"\b\d{3,4}\b"
    },
    {
        'id': 'address',
        'name': 'Address',
        'description': 'Physical addresses',
        'category': Category.PERSONAL,
        'sensitivity': Sensitivity.MEDIUM,
        'regex': r"\d+\s+\w+(\s+\w+)*\s+(Street|St|Avenue|Ave|Road|Rd)\b"
    }
]