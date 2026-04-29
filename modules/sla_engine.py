"""
SLA Engine - tracks time limits per step and triggers escalations.
"""
import json
import os
from datetime import datetime, timezone
from utils.helpers import timestamp_now


def _load_db(db_path):
    if not os.path.exists(db_path):
        return {"applications": {}, "audit_chain": []}
    try:
        with open(db_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return {"applications": {}, "audit_chain": []}


def _save_db(db_path, data):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with open(db_path, "w") as f:
        json.dump(data, f, indent=2)


def start_sla_timer(db_path, app_id, step: str, limit_seconds: int):
    db = _load_db(db_path)
    app = db["applications"].get(app_id, {})
    sla = app.setdefault("sla", {})
    sla[step] = {
        "started_at": timestamp_now(),
        "limit_seconds": limit_seconds,
        "status": "running",
        "escalated": False,
    }
    db["applications"][app_id] = app
    _save_db(db_path, db)


def check_sla(db_path, app_id, step: str) -> dict:
    """Check if SLA for a step has been breached."""
    db = _load_db(db_path)
    app = db["applications"].get(app_id, {})
    sla_info = app.get("sla", {}).get(step)
    if not sla_info:
        return {"status": "not_started"}

    started = datetime.fromisoformat(sla_info["started_at"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    elapsed = (now - started).total_seconds()
    limit = sla_info["limit_seconds"]
    remaining = max(0, limit - elapsed)

    breached = elapsed > limit
    if breached and not sla_info.get("escalated"):
        sla_info["status"] = "breached"
        sla_info["escalated"] = True
        db["applications"][app_id]["sla"][step] = sla_info
        db["applications"][app_id]["status"] = "Delayed - Escalated"
        _save_db(db_path, db)

    return {
        "step": step,
        "elapsed_seconds": int(elapsed),
        "limit_seconds": limit,
        "remaining_seconds": int(remaining),
        "breached": breached,
        "status": "breached" if breached else "running",
    }


def complete_sla_step(db_path, app_id, step: str):
    db = _load_db(db_path)
    app = db["applications"].get(app_id, {})
    if step in app.get("sla", {}):
        app["sla"][step]["status"] = "completed"
        db["applications"][app_id] = app
        _save_db(db_path, db)