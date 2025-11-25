
# scanner/cve_lookup.py

import json
from pathlib import Path
from typing import List

_DB_PATH = Path(__file__).parent / "cve_db.json"
_cve_db = None

def load_cve_db(path: str = None):
    global _cve_db
    p = Path(path) if path else _DB_PATH
    if not p.exists():
        _cve_db = {}
        return _cve_db
    try:
        _cve_db = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        _cve_db = {}
    return _cve_db

def lookup_cves_from_text(text: str) -> List[str]:
    if _cve_db is None:
        load_cve_db()
    out = set()
    if not text:
        return []
    txt = text.lower()
    for pattern, cves in (_cve_db or {}).items():
        if pattern.lower() in txt:
            for c in cves:
                out.add(c)
    return sorted(out)
