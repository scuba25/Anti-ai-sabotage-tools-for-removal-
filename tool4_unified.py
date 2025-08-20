#!/usr/bin/env python3
"""
ASAV-ALL: Unified AI Sabotage Antivirus + Web-Stack Scanner
-----------------------------------------------------------
Features:
1. General Python sabotage detection & auto-fix.
2. Web-stack NGINX/Gunicorn static + runtime probes.
3. Per-file backup (quarantine).
4. Unified JSON report output.
5. CLI subcommands: scan, fix, probe.

Usage:
  # Scan general Python project only
  python asav_all.py scan --path /srv/project

  # Scan + auto-fix
  python asav_all.py fix --path /srv/project --quarantine

  # Probe web stack
  python asav_all.py probe --url http://127.0.0.1 --json report.json
"""
import os, re, sys, json, time, difflib, shutil, socket, ssl
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Callable, Pattern, List, Dict, Any
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

# ----------------- General sabotage rules -----------------
SUPPORTED_EXTS = {".py",".conf",".service",".socket",".yml",".yaml",".toml",".ini",".json",".env",".dockerfile","Dockerfile"}
QUARANTINE_DIR = ".asav_quarantine"

@dataclass
class Rule:
    key: str
    description: str
    pattern: Pattern
    severity: str
    fixer: Optional[Callable[[str], str]] = None

def _fix_bare_except(t:str)->str: return re.sub(r"except\s*:", "except Exception:", t)
def _fix_silent_pass(t:str)->str: return re.sub(r"except[^\n]*\bpass\b", "except Exception as e:\n    raise", t)
def _fix_eval_exec(t:str)->str: return re.sub(r"\b(eval|exec)\(", r"# BLOCKED-\1(", t)
def _fix_debug_true(t:str)->str: return re.sub(r"app\.run\(.*debug\s*=\s*True.*\)", r"app.run(debug=False)", t)

RULES: List[Rule] = [
    Rule("bare_except", "Bare 'except:' masks errors", re.compile(r"except\s*:"), "high", _fix_bare_except),
    Rule("silent_pass", "Exception swallowed with 'pass'", re.compile(r"except[^\n]*\bpass\b"), "high", _fix_silent_pass),
    Rule("eval_exec", "Use of eval/exec", re.compile(r"\b(eval|exec)\("), "high", _fix_eval_exec),
    Rule("debug_true", "Flask debug=True in production", re.compile(r"app\.run\(.*debug\s*=\s*True.*\)"), "high", _fix_debug_true),
]

def file_supported(p:Path)->bool:
    if p.is_dir(): return False
    if p.name == "Dockerfile": return True
    return p.suffix.lower() in SUPPORTED_EXTS or p.name in ("nginx.conf","gunicorn.conf.py","wsgi.py","asgi.py")

def backup(p:Path, root:Path)->Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    qdir = root/QUARANTINE_DIR/ts
    qdir.mkdir(parents=True, exist_ok=True)
    dst = qdir / p.relative_to(root)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, dst)
    return qdir

def save_patch(p:Path, before:str, after:str):
    patch = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=str(p), tofile=str(p)+' (fixed)'))
    (p.parent / (p.name + ".asav.patch")).write_text(patch, encoding="utf-8")

def scan_file(p:Path, root:Path, fix:bool)->Dict[str,Any]:
    try: txt = p.read_text(encoding="utf-8", errors="ignore")
    except Exception as e: return {"path": str(p), "error": str(e), "findings": []}
    original = txt
    findings = []
    for r in RULES:
        if r.pattern.search(txt):
            findings.append({"rule": r.key, "severity": r.severity, "desc": r.description})
            if fix and r.fixer: txt = r.fixer(txt)
    if fix and txt != original:
        backup(p, root)
        p.write_text(txt, encoding="utf-8")
        save_patch(p, original, txt)
    return {"path": str(p), "changed": txt!=original, "findings": findings}

def scan_tree(root:Path, fix:bool)->Dict[str,Any]:
    allres = []
    for p in root.rglob("*"):
        if any(seg in p.parts for seg in (".git","node_modules","venv",".venv",QUARANTINE_DIR)): continue
        if not file_supported(p): continue
        allres.append(scan_file(p, root, fix))
    return {"results":[r for r in allres if r["findings"]]}

# ----------------- Runtime web-stack probes -----------------
def _http_request_raw(host:str, port:int, is_tls:bool, req_line:str, headers:Dict[str,str], body:bytes=b"")->str:
    try:
        sock = socket.create_connection((host, port), timeout=5)
        if is_tls: sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        payload = (req_line + "\r\n" + ''.join(f"{k}: {v}\r\n" for k,v in headers.items()) + "\r\n").encode("utf-8") + body
        sock.sendall(payload)
        sock.settimeout(5)
        chunks=[]
        while True:
            try: chunk = sock.recv(65536)
            except socket.timeout: break
            if not chunk: break
            chunks.append(chunk)
        sock.close()
        return b''.join(chunks).decode("latin1","ignore")
    except Exception as e: return f"ERROR: {e}"

def probe_suite(base_url:str)->Dict[str,Any]:
    u = urlparse(base_url)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme=="https" else 80)
    is_tls = u.scheme=="https"
    out={"target":base_url,"probes":[]}
    
    # TRACE
    out["probes"].append({"name":"TRACE", "evidence":_http_request_raw(host, port, is_tls, f"TRACE {u.path or '/'} HTTP/1.1", {"Host": host})[:400]})
    # Absolute URI
    out["probes"].append({"name":"Absolute-URI GET", "evidence":_http_request_raw(host, port, is_tls, "GET http://example.com/ HTTP/1.1", {"Host": host})[:400]})
    # Directory listing
    dirs = ["/","/static/","/public/","/files/","/.well-known/"]
    dir_results=[]
    for d in dirs:
        r=_http_request_raw(host, port, is_tls, f"GET {d} HTTP/1.1", {"Host": host})
        sig=("Index of /" in r) or ("<title>Index of" in r) or ("autoindex" in r.lower())
        dir_results.append({"path":d,"listing":bool(sig),"snippet":r[:300]})
    out["probes"].append({"name":"Directory listing","details":dir_results})
    # Sensitive paths
    sens=["/.git/HEAD","/.env","/server-status","/nginx_status","/debug","/__debug__"]
    sens_results=[]
    for p in sens:
        r=_http_request_raw(host, port, is_tls, f"GET {p} HTTP/1.1", {"Host": host})
        hit=("ref: refs/heads" in r) or ("dotenv" in r.lower()) or ("Active connections" in r) or ("Werkzeug Debugger" in r)
        sens_results.append({"path":p,"exposed":bool(hit),"snippet":r[:300]})
    out["probes"].append({"name":"Sensitive endpoints","details":sens_results})
    # Server headers
    if requests:
        try:
            resp=requests.get(base_url, timeout=5, verify=False)
            out["probes"].append({"name":"Server header","server":resp.headers.get("Server","<none>")})
        except Exception as e:
            out["probes"].append({"name":"Server header","error":str(e)})
    return out

# ----------------- CLI -----------------
def main():
    import argparse
    ap=argparse.ArgumentParser(description="ASAV-ALL Unified Scanner")
    sub=ap.add_subparsers(dest="cmd",required=True)
    sp_scan=sub.add_parser("scan", help="Static scan")
    sp_scan.add_argument("--path", required=True)
    sp_fix=sub.add_parser("fix", help="Static scan + auto-fix")
    sp_fix.add_argument("--path", required=True)
    sp_fix.add_argument("--quarantine", action="store_true")
    sp_probe=sub.add_parser("probe", help="Web stack runtime probes")
    sp_probe.add_argument("--url", required=True)
    sp_probe.add_argument("--json", default=None)
    args=ap.parse_args()
    
    exit_code=0
    if args.cmd in ("scan","fix"):
        fix=args.cmd=="fix"
        root=Path(args.path).resolve()
        if not root.exists(): print("Path not found",file=sys.stderr); sys.exit(2)
        res=scan_tree(root, fix)
        if res["results"]:
            print("Findings:")
            for r in res["results"]:
                print(f" - {r['path']}")
                for f in r["findings"]:
                    print(f"    [{f['severity']}] {f['rule']}: {f['desc']}")
            exit_code=1
    elif args.cmd=="probe":
        res=probe_suite(args.url)
        print(json.dumps(res,indent=2))
        if args.json: Path(args.json).write_text(json.dumps(res,indent=2))
        exit_code=1
    sys.exit(exit_code)

if __name__=="__main__":
    main()