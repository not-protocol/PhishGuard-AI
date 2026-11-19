"""PhishGuard AI - Flask server.

Run:  python app.py        (binds to 127.0.0.1:5000 only)

Security notes
  * Submitted URLs are parsed, never fetched (no SSRF surface).
  * State-changing requests need a per-session CSRF token and a JSON content type.
  * Message text and full URLs (paths, query strings) are NOT stored. History keeps scores, categories,
    evidence labels and the registered domain of each scanned link.
  * Strict CSP (no inline script/style, no third-party origins) and other hardening headers.
"""
import hmac
import json
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request, session

import ai_summary
import detector as det
import risk_engine

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "phishguard.db"
SCHEMA = """CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, input_type TEXT NOT NULL,
    input_label TEXT NOT NULL, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL,
    category TEXT NOT NULL, report_json TEXT NOT NULL, ai_json TEXT)"""
MAX_BODY_BYTES = 64 * 1024
SUMMARY_LIMIT = (10, 60)  # at most 10 AI summaries per 60 seconds per client


def create_app(db_path=None, detector=None, secret_key=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secret_key or os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DB_PATH=str(db_path or os.environ.get("PHISHGUARD_DB") or DEFAULT_DB),
        MAX_CONTENT_LENGTH=MAX_BODY_BYTES,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
    )
    app.json.sort_keys = False
    app.extensions["detector"] = detector if detector is not None else det.Detector.load()
    app.extensions["summary_hits"] = defaultdict(deque)
    with sqlite3.connect(app.config["DB_PATH"]) as con:
        con.execute(SCHEMA)

    # ------------------------------------------------------------------ helpers
    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        con = g.pop("db", None)
        if con is not None:
            con.close()

    def error(message, status=400):
        return jsonify({"error": message}), status

    def aid(n):
        return f"PG-{n:06d}"

    def parse_aid(value):
        if isinstance(value, str) and value.startswith("PG-") and value[3:].isdigit() and len(value) <= 20:
            return int(value[3:])
        return None

    def save(report, label):
        cur = db().execute(
            "INSERT INTO analyses (created_at, input_type, input_label, risk_score, risk_level, category,"
            " report_json) VALUES (?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), report["input_type"], label,
             report["risk_score"], report["risk_level"], report["threat_category"], json.dumps(report)))
        db().commit()
        report["analysis_id"] = aid(cur.lastrowid)
        return report

    def json_body():
        if not request.is_json:
            return None, error("Content-Type must be application/json.", 415)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return None, error("Request body must be a JSON object.")
        return data, None

    # ------------------------------------------------------------------ hardening
    @app.before_request
    def csrf_and_origin():
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.path.startswith("/api/"):
            origin = request.headers.get("Origin")
            if origin and origin.rstrip("/") not in (f"http://{request.host}", f"https://{request.host}"):
                return error("Cross-origin request rejected.", 403)
            sent = request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                return error("Session expired or CSRF token invalid. Reload the page and try again.", 403)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
        return resp

    @app.errorhandler(413)
    def too_large(_e):
        return error("Request body too large.", 413)

    @app.errorhandler(404)
    def not_found(_e):
        return error("Not found.", 404) if request.path.startswith("/api/") else ("Not found", 404)

    @app.errorhandler(405)
    def bad_method(_e):
        return error("Method not allowed.", 405)

    # ------------------------------------------------------------------ pages and API
    @app.get("/")
    def index():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return render_template("index.html", csrf_token=session["csrf"])

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/models/status")
    def models_status():
        d = app.extensions["detector"]
        out = {"models": d.status, "evaluation": None}
        ev = det.MODEL_DIR / "evaluation.json"
        if ev.exists():
            try:
                r = json.loads(ev.read_text())
                out["evaluation"] = {"synthetic_data": r.get("synthetic_data"),
                                     "message_model": {k: r["message_model"][k] for k in ("f1", "precision", "recall")},
                                     "url_model": {k: r["url_model"][k] for k in ("f1", "precision", "recall")}}
            except (ValueError, KeyError):
                pass
        return jsonify(out)

    @app.get("/api/settings")
    def settings():
        return jsonify({"ai": ai_summary.public_status(), "models": app.extensions["detector"].status,
                        "limits": {"max_message_chars": det.MAX_MESSAGE_LEN, "max_url_chars": det.MAX_URL_LEN}})

    @app.post("/api/analyze/url")
    def analyze_url():
        data, err = json_body()
        if err:
            return err
        try:
            analysis = app.extensions["detector"].analyze_url(data.get("url"))
        except ValueError as exc:
            return error(str(exc))
        report = risk_engine.score_url(analysis)
        return jsonify(save(report, report["registered_domain"]))

    @app.post("/api/analyze/message")
    def analyze_message():
        data, err = json_body()
        if err:
            return err
        try:
            analysis = app.extensions["detector"].analyze_message(data.get("message"))
        except ValueError as exc:
            return error(str(exc))
        report = risk_engine.score_message(analysis)
        return jsonify(save(report, f"Message ({report['char_count']} chars)"))

    @app.post("/api/summary")
    def summary():
        data, err = json_body()
        if err:
            return err
        n = parse_aid(data.get("analysis_id"))
        if n is None:
            return error("A valid analysis_id is required.")
        client = request.remote_addr or "local"
        hits, (limit, window) = app.extensions["summary_hits"][client], SUMMARY_LIMIT
        now = time.monotonic()
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= limit:
            return error("Too many summary requests. Please wait a moment.", 429)
        hits.append(now)
        row = db().execute("SELECT report_json FROM analyses WHERE id=?", (n,)).fetchone()
        if row is None:
            return error("Analysis not found.", 404)
        result = ai_summary.generate(json.loads(row["report_json"]))  # findings come from the DB, not the client
        db().execute("UPDATE analyses SET ai_json=? WHERE id=?", (json.dumps(result), n))
        db().commit()
        return jsonify(result)

    @app.get("/api/history")
    def history():
        rows = db().execute("SELECT id, created_at, input_type, input_label, risk_score, risk_level, category "
                            "FROM analyses ORDER BY id DESC LIMIT 100").fetchall()
        return jsonify([{**dict(r), "analysis_id": aid(r["id"])} for r in rows])

    @app.get("/api/history/<analysis_id>")
    def history_item(analysis_id):
        n = parse_aid(analysis_id)
        row = db().execute("SELECT report_json, ai_json FROM analyses WHERE id=?", (n,)).fetchone() if n else None
        if row is None:
            return error("Analysis not found.", 404)
        report = json.loads(row["report_json"])
        report["analysis_id"] = aid(n)
        return jsonify({"report": report, "ai_summary": json.loads(row["ai_json"]) if row["ai_json"] else None})

    @app.delete("/api/history")
    def clear_history():
        db().execute("DELETE FROM analyses")
        db().commit()
        return jsonify({"status": "cleared"})

    @app.get("/api/stats")
    def stats():
        con = db()
        total = con.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        levels = {r[0]: r[1] for r in con.execute("SELECT risk_level, COUNT(*) FROM analyses GROUP BY risk_level")}
        kinds = {r[0]: r[1] for r in con.execute("SELECT input_type, COUNT(*) FROM analyses GROUP BY input_type")}
        avg = con.execute("SELECT AVG(risk_score) FROM analyses").fetchone()[0]
        return jsonify({"total": total, "avg_score": None if avg is None else round(avg, 1),
                        "levels": {k: levels.get(k, 0) for k in ("low", "medium", "high", "critical")},
                        "types": {"url": kinds.get("url", 0), "message": kinds.get("message", 0)}})

    return app


def _warn_if_models_missing(application):
    for name, st in application.extensions["detector"].status.items():
        if not st["loaded"]:
            print(f"WARNING: {name} not loaded ({st['detail']}). Scores will use rule-based evidence only. "
                  f"Run `python train.py` to create the models.", flush=True)


if __name__ == "__main__":
    _app = create_app()
    _warn_if_models_missing(_app)
    _app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
