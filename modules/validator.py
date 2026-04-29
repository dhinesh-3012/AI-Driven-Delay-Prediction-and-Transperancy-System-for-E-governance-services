"""
Validator / Rule Engine - compares form data vs extracted document data.
Flags mismatches and assigns a risk score.
Now uses fuzzy logic for core string comparisons.
"""
import re
from thefuzz import fuzz


def _similarity(a: str, b: str, method: str = "sort") -> float:
    """Return similarity ratio (0.0 to 1.0) using fuzzy logic."""
    if not a or not b:
        return 0.0
    
    a_clean = a.lower().strip()
    b_clean = b.lower().strip()
    
    if method == "set":
        # token_set_ratio is better for strings of different lengths where one contains the other's words
        return fuzz.token_set_ratio(a_clean, b_clean) / 100.0
    else:
        # token_sort_ratio is robust against word reordering
        return fuzz.token_sort_ratio(a_clean, b_clean) / 100.0


def _normalize_date(d: str) -> str:
    """Normalize date to DD-MM-YYYY."""
    d = re.sub(r"[/\.]", "-", d.strip())
    return d


def validate(form_data: dict, extracted: dict, raw_text: str = "") -> dict:
    """
    Compare form fields vs OCR-extracted data using fuzzy logic.
    If extraction was empty for a field, it performs a 'Global Search' in the raw text.
    """
    flags = []
    passed = []

    def _get_best_val(field_key, form_val):
        """Helper to use extracted value OR search raw_text if missing."""
        ext_val = extracted.get(field_key, "").strip()
        if ext_val:
            return ext_val, "extracted"
        
        # Fallback: Search entire raw text for the form value specifically
        if raw_text and form_val:
            sim = _similarity(form_val, raw_text, method="set")
            if sim >= 0.8: # Very high threshold for global set match
                return form_val, "found in raw text"
        return "", "not found"

    # --- Name check ---
    form_name = form_data.get("name", "").strip()
    doc_name, source = _get_best_val("name", form_name)

    if form_name and doc_name:
        sim = _similarity(form_name, doc_name)
        if sim >= 0.85:
            passed.append({"field": "name", "form": form_name, "doc": doc_name, "note": f"Match ({source})"})
        elif sim >= 0.6:
            flags.append({"field": "name", "form": form_name, "doc": doc_name,
                          "severity": "warning", "note": f"Fuzzy match ({int(sim*100)}%)"})
        else:
            flags.append({"field": "name", "form": form_name, "doc": doc_name,
                          "severity": "error", "note": "Name mismatch"})
    else:
        flags.append({"field": "name", "severity": "warning", "note": "Name not found in document"})

    # --- DOB check ---
    form_dob = _normalize_date(form_data.get("dob", ""))
    doc_dob = _normalize_date(extracted.get("dob", ""))
    
    # Global fallback for DOB if not extracted
    if not doc_dob and raw_text and form_dob:
        if form_dob in _normalize_date(raw_text):
            doc_dob = form_dob

    if form_dob and doc_dob:
        if form_dob == doc_dob:
            passed.append({"field": "dob", "form": form_dob, "doc": doc_dob, "note": "Match"})
        else:
            flags.append({"field": "dob", "form": form_dob, "doc": doc_dob,
                          "severity": "error", "note": "Date of Birth mismatch"})
    else:
        flags.append({"field": "dob", "severity": "warning", "note": "DOB not found in document"})

    # --- Aadhaar check ---
    form_aadhar = re.sub(r"\s", "", form_data.get("aadhaar", ""))
    doc_aadhar = re.sub(r"\s", "", extracted.get("aadhaar", ""))
    
    # Global fallback for Aadhaar
    if not doc_aadhar and raw_text and form_aadhar:
        raw_nos = re.sub(r"\s", "", raw_text)
        if form_aadhar in raw_nos:
            doc_aadhar = form_aadhar

    if form_aadhar and doc_aadhar:
        if form_aadhar == doc_aadhar:
            passed.append({"field": "aadhaar", "note": "Match"})
        else:
            flags.append({"field": "aadhaar", "form": form_aadhar, "doc": doc_aadhar,
                          "severity": "error", "note": "Aadhaar number mismatch"})

    # --- Address check ---
    form_addr = form_data.get("address", "").strip()
    doc_addr = extracted.get("address", "").strip()
    
    # Fallback to fuzzy set match in raw text for address
    if not doc_addr and raw_text and form_addr:
        sim = _similarity(form_addr, raw_text, method="set")
        if sim >= 0.7:
             doc_addr = "[Found in raw text with 70%+ similarity]"

    if form_addr and doc_addr:
        sim = _similarity(form_addr, doc_addr, method="set")
        if sim >= 0.75:
            passed.append({"field": "address", "form": form_addr, "doc": doc_addr, "note": "Fuzzy Match"})
        else:
            flags.append({"field": "address", "form": form_addr, "doc": doc_addr,
                          "severity": "warning", "note": f"Address mismatch ({int(sim*100)}% match)"})
    else:
        flags.append({"field": "address", "severity": "warning", "note": "Address not found in document"})

    # --- Risk score ---
    errors   = sum(1 for f in flags if f.get("severity") == "error")
    warnings = sum(1 for f in flags if f.get("severity") == "warning")
    risk = "high" if errors >= 2 else "medium" if errors == 1 or warnings >= 2 else "low"

    return {
        "flags":   flags,
        "passed":  passed,
        "risk":    risk,
        "summary": f"{errors} error(s), {warnings} warning(s)",
        "auto_approve": risk == "low" and errors == 0,
    }