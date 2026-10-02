import copy
import secrets
import threading

from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from app.engine.assessment import run_scan
from app.engine.crawler import normalize_url


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

lock = threading.Lock()
csrf_token = secrets.token_urlsafe(32)

job = None


@app.before_request
def protect_local_app():
    if request.host not in ("127.0.0.1:5000", "localhost:5000"):
        return jsonify(
            error="Open this app at http://127.0.0.1:5000"
        ), 403

    if request.method == "POST":
        token = request.headers.get("X-CSRF-Token", "")

        if not secrets.compare_digest(token, csrf_token):
            return jsonify(
                error="Refresh the page and try again."
            ), 403


@app.after_request
def add_response_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )

    return response


@app.get("/")
def index():
    return render_template(
        "index.html",
        token=csrf_token,
    )


def scan_worker(current_job):
    def on_message(message):
        with lock:
            current_job["messages"].append(str(message))
            current_job["messages"] = current_job["messages"][-300:]

    try:
        report, path = run_scan(
            current_job["target"],
            on_message=on_message,
        )

        with lock:
            current_job["report"] = report
            current_job["path"] = str(path)
            current_job["status"] = "completed"

    except Exception as exc:
        with lock:
            current_job["error"] = str(exc)
            current_job["status"] = "failed"


@app.post("/api/scan")
def start_scan():
    global job

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(error="Send a JSON object."), 400

    try:
        target = normalize_url(data.get("target"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    with lock:
        if job and job["status"] == "running":
            return jsonify(
                error="A scan is already running."
            ), 409

        job = {
            "id": secrets.token_hex(12),
            "target": target,
            "status": "running",
            "messages": [],
            "report": None,
            "path": None,
            "error": None,
        }

        current_job = job

        try:
            threading.Thread(
                target=scan_worker,
                args=(current_job,),
                daemon=True,
            ).start()

        except Exception:
            current_job["status"] = "failed"
            current_job["error"] = "Could not start the scan."
            return jsonify(error=current_job["error"]), 500

    return jsonify(id=current_job["id"]), 202


@app.get("/api/scan")
def scan_status():
    with lock:
        if job is None:
            return jsonify(status="idle")

        snapshot = copy.deepcopy({
            key: value
            for key, value in job.items()
            if key != "path"
        })

    return jsonify(snapshot)


@app.get("/api/report/<scan_id>")
def download_report(scan_id):
    with lock:
        if (
            not job
            or job["id"] != scan_id
            or job["status"] != "completed"
        ):
            return jsonify(error="Report not available."), 404

        path = job["path"]

    if not Path(path).is_file():
        return jsonify(error="Report file not found."), 404

    return send_file(
        path,
        as_attachment=True,
        mimetype="application/json",
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
    )