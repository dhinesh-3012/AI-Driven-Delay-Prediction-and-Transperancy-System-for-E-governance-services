import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "esevai-middleware-secret-2024")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    EXTRACTED_FOLDER = os.path.join(BASE_DIR, "extracted_data")
    DB_PATH = os.path.join(BASE_DIR, "database", "db.json")
    ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    SLA_LIMITS = {
        "ocr_check":      300,
        "officer_review": 86400,
        "approval":       172800,
    }

    SERVICES = [
        "Income Certificate",
        "Community Certificate",
        "Nativity Certificate",
        "Birth Certificate",
        "Death Certificate",
        "Residence Certificate",
    ]