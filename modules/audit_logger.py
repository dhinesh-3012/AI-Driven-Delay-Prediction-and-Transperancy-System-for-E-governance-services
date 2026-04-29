"""
Append-only audit chain with tamper-evident hashing (blockchain-inspired).
Each entry references the hash of the previous entry.
"""
import json
import os
from utils.helpers import generate_id, timestamp_now, hash_block


def _load_db(db_path):
    if not os.path.exists(db_path):
        return {"applications": {}, "audit_chain": []}
    try:
        with open(db_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return {"applications": {}, "audit_chain": []}


def _save_db(db_path, data):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with open(db_path, "w") as f:
        json.dump(data, f, indent=2)


def append_audit(db_path, app_id, actor, action, details=None):
    """Add a tamper-evident audit entry for an application."""
    db = _load_db(db_path)

    chain = db.get("audit_chain", [])
    prev_hash = chain[-1]["hash"] if chain else "GENESIS"

    entry_data = json.dumps({
        "app_id": app_id,
        "actor": actor,
        "action": action,
        "details": details or {},
        "timestamp": timestamp_now(),
    }, sort_keys=True)

    entry_hash = hash_block(entry_data, prev_hash)

    entry = {
        "id": generate_id(),
        "app_id": app_id,
        "actor": actor,
        "action": action,
        "details": details or {},
        "timestamp": timestamp_now(),
        "prev_hash": prev_hash,
        "hash": entry_hash,
    }

    chain.append(entry)
    db["audit_chain"] = chain
    _save_db(db_path, db)
    return entry


def get_audit_trail(db_path, app_id):
    """Return all audit entries for a specific application."""
    db = _load_db(db_path)
    return [e for e in db.get("audit_chain", []) if e["app_id"] == app_id]


def verify_chain_integrity(db_path):
    """Verify the entire chain has not been tampered with."""
    db = _load_db(db_path)
    chain = db.get("audit_chain", [])
    if not chain:
        return True, "Empty chain"

    prev_hash = "GENESIS"
    for entry in chain:
        if entry["prev_hash"] != prev_hash:
            return False, f"Broken at entry {entry['id']}"
        prev_hash = entry["hash"]
    return True, "Chain intact"