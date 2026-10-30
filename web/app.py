"""NetGuard web layer.

A deliberately thin Flask wrapper: every endpoint writes the policy source to
a temporary file, runs the compiled C binary (bin/netguard) with a timeout and
returns the binary's JSON unchanged.  No compiler or analysis logic lives here.

    POST /api/compile   {source, syntax, min_by?}
    POST /api/classify  {source, syntax, packet}
    POST /api/verify    {source, syntax, n, seed?}
    POST /api/ai-merge  {source, syntax, example?}   (Gemini proposes, netguard equiv proves)
    GET  /api/examples
    GET  /api/status

Run:  python web/app.py   (then open http://127.0.0.1:5000; set PORT to change it)
"""

import json
import os
import subprocess
import tempfile

import ai

from flask import Flask, Response, jsonify, request, send_from_directory

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATIC = os.path.join(HERE, "static")
EXAMPLES = os.path.join(ROOT, "examples")
TIMEOUT_S = int(os.environ.get("NETGUARD_TIMEOUT", "30"))   # seconds per netguard run
MAX_SOURCE = 2 * 1024 * 1024

# Static files are served from the site root, so index.html links them with
# plain relative paths (styles.css, app.js) that also work when the file is
# opened directly from disk.
app = Flask(__name__, static_folder=STATIC, static_url_path="")


@app.after_request
def allow_local_pages(resp):
    # Lets web/static/index.html opened as a file:// page call this local API.
    # The server only listens on 127.0.0.1.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


def find_binary():
    """Locate bin/netguard (or bin/netguard.exe on Windows)."""
    override = os.environ.get("NETGUARD_BIN")
    candidates = [override] if override else []
    candidates += [os.path.join(ROOT, "bin", "netguard.exe"), os.path.join(ROOT, "bin", "netguard")]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def error(message, status):
    return jsonify({"ok": False, "error": message}), status


def read_request():
    """Validate the common {source, syntax} part of a request."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, error("request body must be a JSON object", 400)
    source = data.get("source")
    if not isinstance(source, str):
        return None, error("'source' (string) is required", 400)
    if len(source.encode("utf-8")) > MAX_SOURCE:
        return None, error("source is too large (limit 2 MiB)", 413)
    syntax = data.get("syntax", "fw")
    if syntax not in ("fw", "ng"):
        return None, error("'syntax' must be 'fw' or 'ng'", 400)
    return data, None


def run_netguard(args, source, syntax):
    """Run the binary on `source`; return a Flask response with its JSON."""
    binary = find_binary()
    if binary is None:
        return error(
            "The NetGuard binary was not found (expected bin/netguard or bin/netguard.exe). "
            "Build it first: run 'make' (Linux/macOS/WSL) or 'mingw32-make' (Windows) in the project root.",
            503,
        )
    fd, path = tempfile.mkstemp(suffix="." + syntax, prefix="netguard_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(source)
        cmd = [binary, args[0], path] + args[1:] + ["--syntax", syntax]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return error("netguard timed out after %d s (policy too large?)" % TIMEOUT_S, 504)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    try:
        json.loads(out)
    except ValueError:
        detail = proc.stderr.decode("utf-8", errors="replace").strip() or "no output"
        return error("netguard failed (exit %d): %s" % (proc.returncode, detail[:500]), 500)
    # exit 0 = success, 1 = compile errors (JSON carries the diagnostics), 2 = usage error
    status = 400 if proc.returncode == 2 else 200
    return Response(out, status=status, mimetype="application/json")


@app.route("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.route("/api/status")
def status():
    binary = find_binary()
    return jsonify({"ok": binary is not None, "binary": os.path.relpath(binary, ROOT) if binary else None})


@app.route("/api/examples")
def examples():
    items = []
    for name in sorted(os.listdir(EXAMPLES)):
        if not name.endswith((".fw", ".ng")):
            continue
        with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
            items.append({"name": name, "syntax": name.rsplit(".", 1)[1], "source": f.read()})
    return jsonify({"ok": True, "examples": items})


@app.route("/api/compile", methods=["POST"])
def compile_policy():
    data, err = read_request()
    if err:
        return err
    args = ["compile", "--json"]
    if data.get("min_by") in ("action", "rule"):
        args += ["--min-by", data["min_by"]]
    return run_netguard(args, data["source"], data["syntax"])


@app.route("/api/classify", methods=["POST"])
def classify():
    data, err = read_request()
    if err:
        return err
    packet = data.get("packet")
    if not isinstance(packet, str) or not packet.strip() or len(packet) > 1000:
        return error("'packet' must be a string like 'proto=TCP src_ip=10.0.0.1 dst_ip=8.8.8.8 dst_port=22'", 400)
    return run_netguard(["classify", "--json", "--packet", packet], data["source"], data["syntax"])


@app.route("/api/verify", methods=["POST"])
def verify():
    data, err = read_request()
    if err:
        return err
    try:
        n = int(data.get("n", 10000))
        seed = int(data.get("seed", 42))
    except (TypeError, ValueError):
        return error("'n' and 'seed' must be integers", 400)
    if not 1 <= n <= 200000 or seed < 0:
        return error("'n' must be between 1 and 200000 and 'seed' non-negative", 400)
    return run_netguard(["verify", "--json", "--n", str(n), "--seed", str(seed)], data["source"], data["syntax"])


@app.route("/api/ai-merge", methods=["POST"])
def ai_merge():
    """Gemini proposes a merged policy; `netguard equiv` proves or refutes it."""
    data, err = read_request()
    if err:
        return err
    binary = find_binary()
    if binary is None:
        return error("The NetGuard binary was not found. Build it first with 'make'.", 503)
    example = data.get("example")
    if example is not None and (not isinstance(example, str) or "/" in example or "\\" in example):
        return error("'example' must be a file name", 400)
    try:
        result = ai.ai_merge(binary, data["source"], data["syntax"], example=example,
                             prefer_cache=bool(data.get("replay")))
    except ai.AIError as e:
        return error(str(e), 500)
    except subprocess.TimeoutExpired:
        return error("netguard timed out", 504)
    return jsonify(result), (200 if result.get("ok") else 422)


if __name__ == "__main__":
    if find_binary() is None:
        print("warning: bin/netguard not found -- run 'make' first; the API will return errors until then.")
    port = int(os.environ.get("PORT", "5000"))
    print("NetGuard UI on http://127.0.0.1:%d" % port)
    app.run(host="127.0.0.1", port=port, debug=False)
