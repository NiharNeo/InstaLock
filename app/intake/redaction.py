"""Conservative deterministic masking before any content reaches a model."""
import re
import unicodedata


def redact(text: str) -> str:
    """Mask contact details, long numbers and identifier-like values.

    Detection uses NFKC, ASCII decimal digits, and removes format characters.
    Raw text is retained separately. This is a conservative pattern masker, not
    a claim to recognize every possible personal identifier in arbitrary prose.
    """
    value=unicodedata.normalize('NFKC',text)
    value=''.join(str(unicodedata.decimal(c)) if c.isdecimal() else c for c in value if unicodedata.category(c)!='Cf')
    value=re.sub(r'[^\s<>\[\](),;:]+@[^\s<>\[\](),;:]+','[EMAIL]',value)
    value=re.sub(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b','[ID]',value)
    value=re.sub(r'(?i)\b(?:id|identifier|aadhaar|aadhar|pan|passport|payment[_ -]?id|order[_ -]?id|customer[_ -]?id|account[_ -]?(?:id|number)|ssn)\s*(?:(?:number|no\.?)\s*)?[:=#-]?\s*[^\W_][\w./-]*','[ID]',value)
    value=re.sub(r'(?<!\w)\+?(?:\d[\s().-]*){7,19}(?!\d)','[NUMBER]',value)
    value=re.sub(r'\b(?=[A-Za-z0-9_-]{8,}\b)(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]+\b','[ID]',value)
    return value
