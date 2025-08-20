import os
import re
import time
import difflib
from pathlib import Path
import shutil
import json

# --- sabotage signatures ---
RULES = {
    # Python backend sabotage
    "Bare except": {
        "pattern": r"except\s*:",
        "severity": "high",
        "fix": "except Exception:"
    },
    "Eval/Exec": {
        "pattern": r"\b(eval|exec)\(",
        "severity": "high",
        "fix": "# UNSAFE_DISABLED(\\1("
    },
    "Silent pass": {
        "pattern": r"except.*pass",
        "severity": "medium",
        "fix": "except Exception as e:\n    print(e)"
    },
    "Hardcoded tmp path": {
        "pattern": r"/tmp/",
        "severity": "medium",
        "fix": "os.getenv('TMPDIR','/tmp/')"
    },
    "Hardcoded localhost": {
        "pattern": r"127\.0\.0\.1",
        "severity": "medium",
        "fix": "os.getenv('HOST','127.0.0.1')"
    },
    "Debug mode ON": {
        "pattern": r"app\.run\(.*debug\s*=\s*True.*\)",
        "severity": "high",
        "fix": "app.run(debug=False)"
    },
    "Gunicorn worker overflow": {
        "pattern": r"workers\s*=\s*[0-9]{3,}",
        "severity": "medium",
        "fix": "workers = 4"
    },

    # NGINX sabotage
    "Open proxy": {
        "pattern": r"proxy_pass\s+http://\$\w+;",
        "severity": "high",
        "fix": "# REVIEW: unsafe proxy_pass replaced"
    },
    "Autoindex on": {
        "pattern": r"autoindex\s+on;",
        "severity": "medium",
        "fix": "autoindex off;"
    },
    "Too wide allow": {
        "pattern": r"allow\s+all;",
        "severity": "medium",
        "fix": "# REVIEW: restrict allow"
    },
    "Root in /tmp": {
        "pattern": r"root\s+/tmp",
        "severity": "high",
        "fix": "root /var/www/html;"
    },

    # Docker/systemd sabotage
    "Curl | bash": {
        "pattern": r"curl.*\|.*bash",
        "severity": "high",
        "fix": "# DISABLED: insecure curl|bash"
    },
    "Systemd ExecStart insecure": {
        "pattern": r"ExecStart=.*python.*-m\s+http\.server",
        "severity": "high",
        "fix": "# REPLACE with gunicorn start"
    }
}

QUARANTINE = ".asav_ws_quarantine"

def scan_and_fix(filepath, autofix=False, severity_threshold="low"):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    original = content
    for label, rule in RULES.items():
        if re.search(rule["pattern"], content):
            if severity_allowed(rule["severity"], severity_threshold):
                findings.append((label, rule["severity"]))
            if autofix and "fix" in rule:
                content = re.sub(rule["pattern"], rule["fix"], content)

    if autofix and content != original:
        backup(filepath)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        save_patch(filepath, original, content)

    return findings

def severity_allowed(level, threshold):
    order = {"low":1, "medium":2, "high":3}
    return order[level] >= order[threshold]

def backup(filepath):
    ts = time.strftime("%Y%m%d-%H%M%S")
    dest = Path(QUARANTINE) / ts
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(filepath, dest / Path(filepath).name)

def save_patch(filepath, before, after):
    patchfile = Path(filepath).with_suffix(Path(filepath).suffix + ".asav.patch")
    diff = difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm="")
    with open(patchfile, "w") as f:
        f.write("\n".join(diff))

def scan_tree(root=".", autofix=False, severity_threshold="low"):
    report = {}
    exts = (".py", ".conf", ".service", ".socket", "Dockerfile")
    for dirpath, _, files in os.walk(root):
        if any(skip in dirpath for skip in [".git", "node_modules", "venv"]):
            continue
        for fn in files:
            if fn.endswith(exts) or fn in ["nginx.conf", "gunicorn.conf.py", "wsgi.py