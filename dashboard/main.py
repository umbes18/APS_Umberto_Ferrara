from flask import Flask, render_template
import sqlite3, os, datetime

app = Flask(__name__, template_folder="templates")

ISSUER_DB  = "/issuer_data/academic_records.db"
WALLET_DB  = "/wallet_data/wallet_logs.db"

def rows_from(db_path, source):
    """Ritorna la lista di dizionari dalla tabella logs, aggiungendo la colonna 'source'."""
    if not os.path.exists(db_path):
        return []
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM logs")
    rows = [dict(r) | {"source": source} for r in cur.fetchall()]
    con.close()
    return rows

@app.route("/dashboard", methods=["GET"])
def unified_dashboard():
    issuer_logs  = rows_from(ISSUER_DB, "issuer")
    wallet_logs  = rows_from(WALLET_DB, "wallet")
    merged = sorted(issuer_logs + wallet_logs,
                    key=lambda r: r["created_at"],
                    reverse=True)
    return render_template("unified_dashboard.html", logs=merged)

# optional: health-check endpoint
@app.get("/healthz")
def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}

if __name__ == "__main__":
    # debug solo in sviluppo
    app.run(host="0.0.0.0", port=8000, debug=True)
