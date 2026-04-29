import os
import uuid
import hashlib
from datetime import datetime


def generate_id():
    return str(uuid.uuid4())[:8].upper()


def allowed_file(filename, allowed_extensions):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def timestamp_now():
    return datetime.utcnow().isoformat() + "Z"


def hash_block(data: str, prev_hash: str) -> str:
    combined = prev_hash + data
    return hashlib.sha256(combined.encode()).hexdigest()


def ensure_dirs(*paths):
    for path in paths:
        os.makedirs(path, exist_ok=True)


def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"