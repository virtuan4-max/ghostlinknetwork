"""
GhostLink Network — Flask Web Application
"""
import os, sys, json, uuid, queue, threading, subprocess
from flask import Flask, render_template, request, Response, jsonify, send_file, abort

app = Flask(__name__)

# In-memory session store: session_id -> {queue, done, returncode, output_file}
sessions: dict = {}
_sessions_lock = threading.Lock()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/launch")
def launch():
    return render_template("launch.html")

@app.route("/visualizer")
def visualizer():
    return render_template("visualizer.html")

# ── Bot API ───────────────────────────────────────────────────────────────────

@app.route("/api/start_bot", methods=["POST"])
def start_bot():
    data = request.get_json(force=True) or {}
    token  = data.get("token", "").strip()
    invite = data.get("invite", "").strip()
    depth  = int(data.get("depth", 2))
    delay  = float(data.get("delay", 3.0))

    if not token or not invite:
        return jsonify({"error": "token and invite are required"}), 400

    session_id  = str(uuid.uuid4())
    output_dir  = os.path.join(os.path.dirname(__file__), "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{session_id}.json")

    q = queue.Queue()
    with _sessions_lock:
        sessions[session_id] = {
            "queue":       q,
            "done":        False,
            "returncode":  None,
            "output_file": output_file,
        }

    def _run():
        bot_path = os.path.join(os.path.dirname(__file__), "bot.py")
        cmd = [
            sys.executable, bot_path,
            "--token",  token,
            "--invite", invite,
            "--depth",  str(depth),
            "--delay",  str(delay),
            "--output", output_file,
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in proc.stdout:
                q.put(line.rstrip("\n"))
            proc.wait()
            sessions[session_id]["returncode"] = proc.returncode
        except Exception as exc:
            q.put(f"[ERROR] Failed to launch bot: {exc}")
            sessions[session_id]["returncode"] = -1
        finally:
            sessions[session_id]["done"] = True
            q.put(None)  # sentinel — stream loop exits

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({"session_id": session_id})


@app.route("/api/stream/<session_id>")
def stream(session_id):
    with _sessions_lock:
        sess = sessions.get(session_id)
    if not sess:
        return abort(404)

    def _generate():
        q = sess["queue"]
        while True:
            try:
                line = q.get(timeout=60)
            except queue.Empty:
                yield "data: [STREAM TIMEOUT]\n\n"
                break
            if line is None:          # sentinel from bot thread
                rc = sess.get("returncode", -1)
                yield f"data: __DONE__{rc}\n\n"
                break
            # Escape the line so SSE doesn't break on newlines inside JSON strings
            yield f"data: {json.dumps(line)}\n\n"

    return Response(
        _generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/download/<session_id>")
def download(session_id):
    with _sessions_lock:
        sess = sessions.get(session_id)
    if not sess:
        return abort(404)
    f = sess.get("output_file")
    if not f or not os.path.exists(f):
        return abort(404)
    return send_file(f, as_attachment=True, download_name="ecosystem.json")


@app.route("/api/check/<session_id>")
def check(session_id):
    with _sessions_lock:
        sess = sessions.get(session_id)
    if not sess:
        return abort(404)
    f = sess.get("output_file", "")
    return jsonify({
        "done":       sess["done"],
        "returncode": sess.get("returncode"),
        "has_file":   os.path.exists(f) if f else False,
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("GhostLink Network — Flask server starting on http://127.0.0.1:5000")
    app.run(debug=True, port=5000, threaded=True)
