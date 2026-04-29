"""
Data Extractor - parses structured fields from raw OCR text.
"""
import re


PATTERNS = {
    "name": [
        r"Name[:\s]+([A-Z][a-z\s\.]+)",
        r"Applicant[:\s]+([A-Z][a-z\s\.]+)",
        # Heuristic: Find text after "To" specifically on Aadhaar cards
        r"To\s*\n+([A-Z][A-Za-z\s]+)",
        # Heuristic: Capitalized lines that look like names
        r"([A-Z]{3,}\s[A-Z]{3,}(?:\s[A-Z])?)\b",
    ],
    "dob": [
        r"Date of Birth[:\s/]+([\d\-/\.]+)",
        r"DOB[:\s/]+([\d\-/\.]+)",
        r"D\.O\.B[:\s/]+([\d\-/\.]+)",
    ],
    "address": [
        # Match "Address:" but ensure it doesn't match the "should be updated" instruction
        r"Address[:\s]*(?!\s*should\s+be\s+updated)(.+?)(?:\n\n|Aadhaar|Community|$)",
        r"Address[:\s]*(.+?)(?:\n\n|Aadhaar|Community|$)",
    ],
    "aadhaar": [
        r"Aadhaar[:\s]+([\d\s]{12,16})",
        r"Aadhar[:\s]+([\d\s]{12,16})",
        # Match 12 digits directly (4-4-4 format)
        r"\b(\d{4}\s\d{4}\s\d{4})\b",
    ],
    "community": [
        r"Community[:\s]+([A-Za-z/\s]+)",
        r"Caste[:\s]+([A-Za-z/\s]+)",
    ],
    "income": [
        r"Income[:\s]+Rs\.?\s*([\d,]+)",
        r"Annual Income[:\s]+Rs\.?\s*([\d,]+)",
    ],
}


def extract_fields(raw_text: str) -> dict:
    """Extract key fields from OCR text using regex patterns."""
    extracted = {}

    for field, patterns in PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, raw_text, re.IGNORECASE | re.DOTALL)
            if match:
                value = match.group(1).strip().strip(",").strip()
                # Trim excessively long matches
                if len(value) > 100:
                    value = value[:100]
                extracted[field] = value
                break

    return extracted