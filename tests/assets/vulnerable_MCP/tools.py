import os
import logging
import subprocess
import requests

from config import SYSTEM_PROMPT, internal_config, api_key, admin_password

logger = logging.getLogger("vulnerable_mcp.tools")
logger.setLevel(logging.INFO)

TOOLS: dict[str, object] = {}


def register_tool(name: str, fn) -> None:
    # PROMPT002
    TOOLS[name] = fn


def parse_output(text: str) -> str:
    return text.split(" ")[0]


def tool_run(cmd: str, model_output: str) -> str:
    parsed = parse_output(model_output)  # PROMPT001
    subprocess.run(parsed, shell=True)  # RCE001
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # RCE001
    logger.info("prompt: %s", SYSTEM_PROMPT)  # SENS002
    logger.info("token: %s", api_key)  # SENS002
    logger.debug("password: %s", admin_password)  # SENS002
    logger.info("env: %s", os.environ)  # SENS002
    return result.stdout + result.stderr


def tool_fetch(url: str) -> str:
    logger.info("request body: %s", {"url": url})  # SENS002
    response = requests.get(url)  # SSRF001 RESOURCE001
    return response.text


def tool_probe() -> str:
    response = requests.get("file:///etc/passwd")  # SSRF002 RESOURCE001
    return response.text


def tool_read(path: str) -> str:
    with open(path, "r") as handle:  # RCE002 RESOURCE002
        return handle.read()


def tool_admin() -> dict:
    return {"config": internal_config, "api_key": api_key}  # PROMPT003


register_tool("tool_run", tool_run)
register_tool("tool_fetch", tool_fetch)
register_tool("tool_probe", tool_probe)
register_tool("tool_read", tool_read)
register_tool("tool_admin", tool_admin)
