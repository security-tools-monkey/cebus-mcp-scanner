"""
Language-specific pattern definitions for security rules.

Rules use these patterns to detect security issues across different languages.
Patterns are organized by rule category and can be customized via configuration.
"""

from __future__ import annotations

from typing import Dict, List

# Shell execution patterns
SHELL_EXECUTION_PATTERNS: Dict[str, List[str]] = {
    "python": [
        "os.system",
        "os.popen",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.check_call",
        "subprocess.check_output",
    ],
    "javascript": [
        "child_process.exec",
        "child_process.spawn",
        "child_process.execFile",
        "child_process.fork",
        "child_process.execSync",
        "child_process.spawnSync",
        "child_process.execFileSync",
        "execSync",
        "spawnSync",
        "execFileSync",
    ],
    "typescript": [
        "child_process.exec",
        "child_process.spawn",
        "child_process.execFile",
        "child_process.fork",
        "child_process.execSync",
        "child_process.spawnSync",
        "child_process.execFileSync",
        "execSync",
        "spawnSync",
        "execFileSync",
    ],
    "go": [
        "os/exec.Command",
        "exec.Command",
        "exec.CommandContext",
        "Cmd.Run",
        "Cmd.Start",
    ],
}

# HTTP client patterns
HTTP_CLIENT_PATTERNS: Dict[str, List[str]] = {
    "python": [
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.head",
        "requests.options",
        "requests.patch",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.delete",
        "httpx.head",
        "httpx.options",
        "httpx.patch",
        "httpx.request",
        "urllib.urlopen",
        "urllib.request.urlopen",
    ], # TODO: sessions
    "javascript": [
        "fetch",
        "got",
        "got.get",
        "got.post",
        "got.put",
        "got.delete",
        "got.head",
        "got.options",
        "got.patch",
        "got.request",
        "axios.get",
        "axios.post",
        "axios.put",
        "axios.delete",
        "axios.head",
        "axios.options",
        "axios.patch",
        "axios.request",
        "http.get",
        "http.post",
        "https.get",
        "https.post",
        "undici.request",
        "undici.fetch",
        "nodeFetch",
        "request.get",
        "request.post",
    ],
    "typescript": [
        "fetch",
        "got",
        "got.get",
        "got.post",
        "got.put",
        "got.delete",
        "got.head",
        "got.options",
        "got.patch",
        "got.request",
        "axios.get",
        "axios.post",
        "axios.put",
        "axios.delete",
        "axios.head",
        "axios.options",
        "axios.patch",
        "axios.request",
        "http.get",
        "http.post",
        "https.get",
        "https.post",
        "undici.request",
        "undici.fetch",
        "nodeFetch",
    ],
    "go": [
        "http.Get",
        "http.Post",
        "http.Put",
        "http.Delete",
        "http.Head",
        "http.Options",
        "http.Patch",
        "http.Client.Get",
        "http.Client.Post",
        "http.Client.Do",
        "net/http.Get",
        "net/http.Post",
        "net/http",
    ],
}

# File access patterns
FILE_ACCESS_PATTERNS: Dict[str, List[str]] = {
    "python": [
        "open",
        "Path",
        "pathlib.Path",
        "os.open",
        "os.remove",
        "os.unlink",
    ],
    "javascript": [
        "fs.readFile",
        "fs.writeFile",
        "fs.open",
        "fs.createReadStream",
        "fs.createWriteStream",
        "fs.promises.readFile",
        "fs.promises.writeFile",
        "fs.promises.open",
        "fs.promises.access",
        "fs.promises.appendFile",
    ],
    "typescript": [
        "fs.readFile",
        "fs.writeFile",
        "fs.open",
        "fs.createReadStream",
        "fs.createWriteStream",
        "fs.promises.readFile",
        "fs.promises.writeFile",
        "fs.promises.open",
        "fs.promises.access",
        "fs.promises.appendFile",
    ],
    "go": [
        "os.Open",
        "os.Create",
        "os.OpenFile",
        "ioutil.ReadFile",
        "ioutil.WriteFile",
        "os.ReadFile",
    ],
}

# Dangerous URL scheme patterns
DANGEROUS_URL_SCHEMES: List[str] = [
    "file://",
    "ftp://",
    "gopher://",
    "ldap://",
    "jar://",
]

# Secret detection patterns (regex-based, language-agnostic)
SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]",
]
