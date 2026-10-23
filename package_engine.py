import os
import json
import hashlib
import duckdb
import requests
import zipfile
import io
from datetime import datetime, timezone

DB_FILE = "data/package_compromise.db"
HISTORY_DIR = "data/history"
EXPORT_DIR = "public"
API_DIR = os.path.join(EXPORT_DIR, "v1")
OSV_MALICIOUS_URL = "https://osv-vulnerabilities.storage.googleapis.com/Malicious%20Packages/all.zip"

def compute_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

def fetch_osv_malicious_packages():
    res = requests.get(OSV_MALICIOUS_URL, timeout=30)
    if res.status_code != 200:
        return []
    
    events = []
    with zipfile.ZipFile(io.BytesIO(res.content)) as z:
        for filename in z.namelist():
            if filename.endswith(".json"):
                data = json.loads(z.read(filename))
                events.append(data)
    return events

def serialize_row(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        elif k == "raw_json" and isinstance(v, str):
            try:
                out[k] = json.loads(v)
            except Exception:
                out[k] = v
        else:
            out[k] = v
    return out

def build_static_api(conn):
    os.makedirs(API_DIR, exist_ok=True)
    now_iso = datetime.now(timezone.utc).isoformat()
    
    cur = conn.execute("SELECT * FROM security_events ORDER BY modified_date DESC LIMIT 100")
    cols = [desc[0] for desc in cur.description]
    recent_events = [serialize_row(dict(zip(cols, row))) for row in cur.fetchall()]
    
    with open(os.path.join(API_DIR, "active-alerts.json"), "w", encoding="utf-8") as f:
        json.dump({"metadata": {"updated_at": now_iso}, "alerts": recent_events}, f, indent=2)
        
    cur = conn.execute(f"SELECT * FROM security_events WHERE published_date >= '{datetime.now(timezone.utc).strftime('%Y-%m-%d')}' ORDER BY published_date DESC")
    today_events = [serialize_row(dict(zip(cols, row))) for row in cur.fetchall()]
    
    with open(os.path.join(API_DIR, "compromised-today.json"), "w", encoding="utf-8") as f:
        json.dump({"metadata": {"updated_at": now_iso}, "alerts": today_events}, f, indent=2)

    lines = [
        "# Package Compromise Wire",
        f"> Last Sync: {now_iso} UTC",
        "> Source: OSV Malicious Packages",
        "",
        "## Active Supply Chain Compromises (Latest 25)"
    ]
    for e in recent_events[:25]:
        lines.append(f"- **{e['ecosystem']}/{e['package_name']}** ({e['event_id']}) - {e['summary']} *(Updated: {e['modified_date']})*")
        
    with open(os.path.join(EXPORT_DIR, "llms.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    html = f"""<!DOCTYPE html><html><head><title>Package Compromise Wire</title></head>
    <body style='font-family:sans-serif;padding:2rem;line-height:1.6;'>
    <h1>🚨 Package Compromise Wire</h1>
    <p>Machine-first temporal wire tracking malicious packages and supply chain compromises.</p>
    <ul>
      <li><a href='v1/active-alerts.json'>/v1/active-alerts.json</a></li>
      <li><a href='v1/compromised-today.json'>/v1/compromised-today.json</a></li>
      <li><a href='llms.txt'>llms.txt</a></li>
      <li><a href='compromises.parquet'>compromises.parquet</a></li>
    </ul></body></html>"""
    with open(os.path.join(EXPORT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)

def run():
    os.makedirs("data", exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(EXPORT_DIR, exist_ok=True)
    
    conn = duckdb.connect(DB_FILE)
    with open("schema.sql", "r", encoding="utf-8") as f:
        conn.execute(f.read())

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    date_str = now.strftime("%Y-%m-%d")
    year_str = now.strftime("%Y")
    month_str = now.strftime("%m")

    events = fetch_osv_malicious_packages()
    events.sort(key=lambda x: x.get("modified", ""), reverse=True)
    
    month_dir = os.path.join(HISTORY_DIR, year_str, month_str)
    os.makedirs(month_dir, exist_ok=True)
    daily_history_file = os.path.join(month_dir, f"{date_str}.jsonl")
    
    conn.execute("BEGIN TRANSACTION")
    
    for event in events[:500]:
        event_id = event.get("id")
        published = event.get("published", "")
        modified = event.get("modified", "")
        summary = event.get("summary", "").replace("'", "''")
        
        affected = event.get("affected", [{}])[0]
        pkg = affected.get("package", {})
        ecosystem = pkg.get("ecosystem", "UNKNOWN")
        pkg_name = pkg.get("name", "UNKNOWN")
        
        content_hash = compute_hash(event)
        raw_json = json.dumps(event).replace("'", "''")
        
        exists = conn.execute(f"SELECT 1 FROM security_events WHERE event_id = '{event_id}' AND content_hash = '{content_hash}'").fetchone()
        
        if not exists:
            conn.execute(f"""
                INSERT OR REPLACE INTO security_events 
                (event_id, ecosystem, package_name, summary, published_date, modified_date, content_hash, raw_json)
                VALUES ('{event_id}', '{ecosystem}', '{pkg_name}', '{summary}', '{published}', '{modified}', '{content_hash}', '{raw_json}')
            """)
            
            commit_id = conn.execute("SELECT nextval('seq_commit_id')").fetchone()[0]
            conn.execute(f"""
                INSERT INTO ledger (commit_id, timestamp_utc, operation, event_id, ecosystem, package_name) 
                VALUES ({commit_id}, '{now_iso}', 'COMPROMISE_DETECTED', '{event_id}', '{ecosystem}', '{pkg_name}')
            """)
            
            ledger_entry = {
                "commit_id": commit_id, "timestamp_utc": now_iso, "operation": "COMPROMISE_DETECTED",
                "event_id": event_id, "ecosystem": ecosystem, "package_name": pkg_name, "content_hash": content_hash
            }
            with open(daily_history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(ledger_entry) + "\n")

    conn.execute("COMMIT")
    
    conn.execute(f"COPY (SELECT * FROM security_events) TO '{EXPORT_DIR}/compromises.parquet' (FORMAT PARQUET)")
    build_static_api(conn)
    conn.close()

if __name__ == "__main__":
    run()
