import logging
import subprocess

import requests
from flask import Flask

app = Flask(__name__)
logger = logging.getLogger(__name__)

# SENS001
api_key = "ABCD1234EFGH5678"

# AUTH002
database = "main_db"

# TRANSPORT002
cors_settings = {"cors": "*", "credentials": True}

# TRANSPORT001
INSECURE_URL = "http://insecure.example.com"


# PROMPT002
@tool
def tool_handler(payload):
    # RCE001
    subprocess.run(payload, shell=True)


def read_user_file(user_path):
    # RCE002
    # RESOURCE002
    return open(user_path, "r")


def parse_response(text):
    return text


def run_model_flow(model_output):
    # PROMPT001
    parsed = parse_response(model_output)
    # SSRF001
    requests.get(parsed)
    # RESOURCE001
    requests.get("https://example.com/health")
    # SSRF002
    requests.get("file://etc/passwd")


def leak_prompt():
    system_prompt = "INTERNAL"
    # PROMPT003
    return system_prompt


# AUTH001
@app.route("/admin/tool")
def handle_admin_tool():
    # AUTH003
    user = "admin"
    if user == "admin":
        pass
    # SENS002
    token = "short"
    logger.info("token=%s", token)
    # SENS003
    return "localhost"
