import logging
from flask import Flask, request, jsonify

from config import SYSTEM_PROMPT, internal_config, api_key
from storage import init_storage, append_event, fetch_events
from tools import tool_run, tool_fetch, tool_read, tool_probe, tool_admin

app = Flask(__name__)
logger = logging.getLogger("vulnerable_mcp.server")
logger.setLevel(logging.INFO)

CORS_SETTINGS = {"cors": {"origins": "*", "credentials": True}}  # TRANSPORT002

bypass_auth = True  # AUTH003


def is_trusted(user: str) -> bool:
    if user == "admin":  # AUTH003
        return True
    if user == "test":  # AUTH003
        return True
    return False


# AUTH001
@app.route("/tool/run", methods=["POST"])
def handle_run():
    payload = request.get_json(force=True)
    system_prompt = payload.get("system_prompt", SYSTEM_PROMPT)
    cmd = payload.get("cmd", "")
    model_output = payload.get("model_output", "")
    result = tool_run(cmd, model_output)
    append_event(str(payload))
    return jsonify({"system_prompt": system_prompt, "internal_url": "http://localhost:9000/callback", "result": result, "config": internal_config})  # PROMPT003 SENS003 TRANSPORT001


@app.route("/tool/fetch", methods=["POST"])
def handle_fetch():
    payload = request.get_json(force=True)
    url = payload.get("url", "")
    body = tool_fetch(url)
    return jsonify({"system_prompt": payload.get("system_prompt", SYSTEM_PROMPT), "body": body, "reply": "http://localhost:9000/fetch"})  # PROMPT003 SENS003 TRANSPORT001


@app.route("/tool/read", methods=["POST"])
def handle_read():
    payload = request.get_json(force=True)
    path = payload.get("path", "")
    data = tool_read(path)
    return jsonify({"data": data, "system_prompt": payload.get("system_prompt", SYSTEM_PROMPT)})  # PROMPT003


@app.route("/tool/probe", methods=["POST"])
def handle_probe():
    result = tool_probe()
    return jsonify({"result": result, "system_prompt": SYSTEM_PROMPT})  # PROMPT003


@app.route("/tool/admin", methods=["GET"])
def handle_admin():
    return jsonify({"config": internal_config, "api_key": api_key, "system_prompt": SYSTEM_PROMPT})  # PROMPT003


@app.route("/tool/events", methods=["GET"])
def handle_events():
    return jsonify({"events": fetch_events(), "system_prompt": SYSTEM_PROMPT})  # PROMPT003


def run() -> None:
    init_storage()
    app.run(host="0.0.0.0", port=8000)


if __name__ == "__main__":
    run()
