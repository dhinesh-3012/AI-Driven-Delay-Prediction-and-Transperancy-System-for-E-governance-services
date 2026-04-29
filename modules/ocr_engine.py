"""
OCR Engine - extracts text from uploaded documents (PDF/image).
Falls back to mock extraction if tesseract is not installed.
"""
import os
import re

try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

try:
    from pdf2image import convert_from_path
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


def extract_text_from_file(filepath: str) -> str:
    """Extract raw text from image or PDF file."""
    ext = filepath.rsplit(".", 1)[-1].lower()

    if not OCR_AVAILABLE:
        return _mock_text(filepath)

    try:
        if ext == "pdf":
            if PDF_AVAILABLE:
                pages = convert_from_path(filepath, dpi=200)
                return "\n".join(
                    pytesseract.image_to_string(page) for page in pages
                )
            else:
                return _mock_text(filepath)
        else:
            img = Image.open(filepath)
            return pytesseract.image_to_string(img)
    except Exception as e:
        return f"[OCR ERROR: {e}]"


def _mock_text(filepath: str) -> str:
    """Return realistic mock OCR text for demo purposes."""
    filename = os.path.basename(filepath).lower()
    return (
        "GOVERNMENT OF TAMIL NADU\n"
        "Name: Ravi Kumar\n"
        "Date of Birth: 15-08-1995\n"
        "Address: 12, Gandhi Street, Chennai - 600001\n"
        "Aadhaar Number: 1234 5678 9012\n"
        "Community: OBC\n"
        "Annual Income: Rs. 1,20,000\n"
        "Issued by: Revenue Department\n"
    )