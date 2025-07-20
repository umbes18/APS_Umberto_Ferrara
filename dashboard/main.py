from flask import Flask, render_template
import sqlite3, os, datetime

app = Flask(__name__, template_folder="templates")

ISSUER_DB   = "/issuer_data/academic_records.db"
WALLET_DB   = "/wallet_data/wallet_logs.db"
VERIFIER_DB = "/verifier_data/verifier_logs.db"

def rows_from(db_path: str, source: str):
    if not os.path.exists(db_path):
        return []
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = [dict(r) | {"source": source}           # aggiunge la colonna “source”
            for r in con.execute("SELECT * FROM logs").fetchall()]
    con.close()
    return rows

@app.route("/dashboard")
def unified_dashboard():
    issuer_logs   = rows_from(ISSUER_DB,   "issuer")
    wallet_logs   = rows_from(WALLET_DB,   "wallet")
    verifier_logs = rows_from(VERIFIER_DB, "verifier")
    merged = sorted(issuer_logs + wallet_logs + verifier_logs,
                    key=lambda r: r["created_at"], reverse=True)
    return render_template("unified_dashboard.html", logs=merged)

@app.get("/healthz")
def health():
    return {"status": "ok",
            "time": datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z"}
