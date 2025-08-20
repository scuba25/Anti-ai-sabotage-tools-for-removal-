#!/usr/bin/env python3
"""
AI Sabotage Antivirus (ASAV)
----------------------------
Scan codebases for AI-introduced sabotage patterns and optionally remove/fix them.
Features:
- Signature (regex) + heuristic checks
- Auto-fixes for common issues (bare except, eval/exec, placeholders, hardcoded paths)
- Quarantine with backups and unified-diff patches for easy rollback
- Configurable severities and allowlist/denylist
- CI-friendly JSON report

Usage:
  python ai_sabotage_antivirus.py --path .                 # scan only
  python ai_sabotage_antivirus.py --path . --fix           # scan + auto-fix (writes changes)
  python ai_sabotage_antivirus.py --path . --fix --quarantine  # also save originals to .asav_quarantine
  python ai_sabotage_antivirus.py --restore-last           # restore last quarantined snapshot

Exit codes:
  0 = no findings
  1 = findings present (scan mode) or fixes applied (fix mode)
  2 = error
"""

import os, re, json, sys, shutil, hashlib, difflib, time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional, Pattern, Any

SUPPORTED_EXTS = {".py",".js",".ts",".tsx",".jsx",".java",".go",".rs",".c",".cpp",".h",".hpp",
                  ".rb",".php",".cs",".kt",".m",".swift",".scala",".sh",".ps1",".yaml",".yml",
                  ".toml",".ini",".conf",".json",".env",".dockerfile","Dockerfile"}

QUARANTINE_DIR = ".asav_quarantine"

@dataclass
class Rule:
    key: str
    description: str
    pattern: Pattern
    severity: str  # "low" | "medium" | "high" | "critical"
    fixer: Optional[Callable[[str], str]] = None

def _fix_bare_except(text:str)->str:
    return re.sub(r"except\s*:", "except Exception:", text)

def _fix_silent_pass(text:str)->str:
    return re.sub(r"except\s+([^\n:]+)?:\s*pass", r"except \1:\n    # ASAV: raised to avoid silent swallow\n    raise", text)

def _fix_eval_exec(text:str)->str:
    return re.sub(r"\b(eval|exec)\(", r"# ASAV-BLOCKED-\1(", text)

def _fix_placeholders(text:str)->str:
    return re.sub(r"(TODO|XXX|your_api_key_here|replace_me)", "<REPLACE_ME>", text, flags=re.IGNORECASE)

def _fix_tmp_paths(text:str)->str:
    text = re.sub(r"(?<![A-Za-z0-9_])/tmp/", "os.getenv('TMPDIR', '/tmp/')/", text)
    text = re.sub(r"127\.0\.0\.1", "os.getenv('HOST','127.0.0.1')", text)
    return text

def _fix_random_seed(text:str)->str:
    # Insert a deterministic seed line before first random call if not present
    if re.search(r"\brandom\.(random|randint|choice|shuffle|uniform)\(", text) and not re.search(r"\brandom\.seed\(", text):
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if re.search(r"\brandom\.(random|randint|choice|shuffle|uniform)\(", line):
                lines.insert(i, "import random  # ASAV\nrandom.seed(42)  # ASAV deterministic seed")
                return "\n".join(lines)
    return text

def _fix_bare_shell(text:str)->str:
    # Comment dangerous curl|bash or powershell iwr|iex pipelines
    text = re.sub(r"(curl\s+[^\n]+?\|\s*(bash|sh))", r"# ASAV-BLOCKED: \1", text, flags=re.IGNORECASE)
    text = re.sub(r"(iwr\s+[^\n]+?\|\s*iex)", r"# ASAV-BLOCKED: \1", text, flags=re.IGNORECASE)
    return text

def _fix_minified_hint(text:str)->str:
    # Can't safely prettify minified files here; add a header marker if looks minified
    if len(text) > 50000 and text.count("\n") < 200:
        return "/* ASAV: suspected minified blob — review provenance */\n" + text
    return text

RULES: List[Rule] = [
    Rule("bare_except", "Bare 'except:' masks real errors", re.compile(r"except\s*:"), "high", _fix_bare_except),
    Rule("silent_pass", "Exception swallowed with 'pass'", re.compile(r"except[^\n]*\bpass\b"), "critical", _fix_silent_pass),
    Rule("eval_exec", "Use of eval/exec is unsafe", re.compile(r"\b(eval|exec)\("), "high", _fix_eval_exec),
    Rule("placeholders", "Placeholders or TODOs left in code", re.compile(r"(TODO|XXX|your_api_key_here|replace_me)", re.IGNORECASE), "medium", _fix_placeholders),
    Rule("hardcoded_tmp_host", "Hardcoded /tmp or 127.0.0.1", re.compile(r"(/tmp/|127\.0\.0\.1)"), "medium", _fix_tmp_paths),
    Rule("random_no_seed", "Random used without fixed seed", re.compile(r"\brandom\.(random|randint|choice|shuffle|uniform)\("), "medium", _fix_random_seed),
    Rule("nested_lambda", "Nested lambdas reduce readability", re.compile(r"lambda.*lambda"), "low", None),
    Rule("dangerous_shell", "curl|bash or iwr|iex pipeline", re.compile(r"(curl\s+[^\n]+?\|\s*(bash|sh))|(iwr\s+[^\n]+?\|\s*iex)", re.IGNORECASE), "high", _fix_bare_shell),
    Rule("minified_blob", "Large, low-newline blob (vendored/minified)", re.compile(r".*", re.DOTALL), "low", _fix_minified_hint),
]

def file_supported(path:Path)->bool:
    if path.is_dir():
        return False
    ext = path.suffix
    name = path.name
    if name == "Dockerfile":
        return True
    return ext.lower() in SUPPORTED_EXTS

def sha256(text:str)->str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()

def snapshot_file(path:Path, qdir:Path)->None:
    qdir.mkdir(parents=True, exist_ok=True)
    rel = Path(".") / path
    target = qdir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target)

def unified_diff(a_text:str, b_text:str, a_path:str, b_path:str)->str:
    return "".join(difflib.unified_diff(
        a_text.splitlines(keepends=True),
        b_text.splitlines(keepends=True),
        fromfile=a_path, tofile=b_path))

def scan_file(path:Path, apply_fixes:bool)->Dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return {"path": str(path), "error": str(e), "findings": []}

    findings = []
    fixed = raw

    for rule in RULES:
        # Special-case minified blob heuristic: only fire if very long and low lines
        if rule.key == "minified_blob":
            if len(raw) > 50000 and raw.count("\n") < 200:
                findings.append({"rule": rule.key, "severity": rule.severity, "desc": rule.description})
                if apply_fixes and rule.fixer:
                    fixed = rule.fixer(fixed)
            continue

        if rule.pattern.search(raw):
            findings.append({"rule": rule.key, "severity": rule.severity, "desc": rule.description})
            if apply_fixes and rule.fixer:
                fixed2 = rule.fixer(fixed)
                fixed = fixed2

    changed = (fixed != raw)
    return {"path": str(path), "findings": findings, "changed": changed, "original": raw if changed else None, "fixed": fixed if changed else None}

def scan_tree(root:Path, apply_fixes:bool, quarantine:bool, exclude:List[str])->Dict[str, Any]:
    results = []
    qstamp = time.strftime("%Y%m%d-%H%M%S")
    qdir = root / QUARANTINE_DIR / qstamp if quarantine else None

    for p in root.rglob("*"):
        if any(str(p).startswith(ex) for ex in exclude):
            continue
        if not file_supported(p):
            continue

        report = scan_file(p, apply_fixes)
        if "error" in report and report["error"]:
            results.append(report)
            continue

        if report["findings"]:
            if quarantine and report.get("changed") and report.get("original") is not None:
                snapshot_file(p, qdir)
            if apply_fixes and report.get("changed") and report.get("fixed") is not None:
                # write fix and produce a .patch alongside
                patch = unified_diff(report["original"], report["fixed"], str(p), str(p)+" (fixed)")
                p.write_text(report["fixed"], encoding="utf-8")
                patch_path = Path(str(p) + ".asav.patch")
                patch_path.write_text(patch, encoding="utf-8")
                report["patch"] = str(patch_path)
            results.append({k:v for k,v in report.items() if k not in ("original","fixed")})
    return {"results": results, "quarantine": str(qdir) if qdir else None}

def restore_last_quarantine(root:Path)->bool:
    qroot = root / QUARANTINE_DIR
    if not qroot.exists():
        print("No quarantine snapshots found.")
        return False
    snaps = sorted([p for p in qroot.iterdir() if p.is_dir()], reverse=True)
    if not snaps:
        print("No quarantine snapshots found.")
        return False
    last = snaps[0]
    for src in last.rglob("*"):
        if src.is_dir():
            continue
        rel = src.relative_to(last)
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    print(f"Restored from snapshot: {last}")
    return True

def main():
    import argparse
    ap = argparse.ArgumentParser(description="AI Sabotage Antivirus (ASAV)")
    ap.add_argument("--path", default=".", help="Path to scan (default: .)")
    ap.add_argument("--fix", action="store_true", help="Apply auto-fixes")
    ap.add_argument("--quarantine", action="store_true", help="Quarantine originals before fixing")
    ap.add_argument("--exclude", action="append", default=[f"./{QUARANTINE_DIR}","./.git","./node_modules","./venv","./.venv"], help="Paths to exclude (repeatable)")
    ap.add_argument("--report-json", default=None, help="Write JSON report to given path")
    ap.add_argument("--severity-threshold", default="low", choices=["low","medium","high","critical"], help="Minimum severity to include in results")
    ap.add_argument("--restore-last", action="store_true", help="Restore last quarantine snapshot")
    args = ap.parse_args()

    root = Path(args.path).resolve()

    if args.restore_last:
        ok = restore_last_quarantine(root)
        sys.exit(0 if ok else 2)

    severities = {"low":0,"medium":1,"high":2,"critical":3}
    threshold = severities[args.severity_threshold]

    data = scan_tree(root, apply_fixes=args.fix, quarantine=args.quarantine, exclude=args.exclude)

    # Filter by severity threshold
    filtered = []
    for item in data["results"]:
        item["findings"] = [f for f in item["findings"] if severities.get(f["severity"],0) >= threshold]
        if item["findings"]:
            filtered.append(item)
    data["results"] = filtered

    if args.report_json:
        Path(args.report_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_json).write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Pretty print summary
    if not data["results"]:
        print("✅ No findings.")
        sys.exit(0)
    else:
        print("⚠️ Findings:")
        for item in data["results"]:
            print(f"\n{item['path']}")
            for f in item["findings"]:
                print(f"  - [{f['severity']}] {f['rule']}: {f['desc']}")
            if args.fix:
                print("  * Fixed and patch saved at:", item.get("patch","<none>"))
        if args.report_json:
            print(f"\nJSON report written to: {args.report_json}")
        sys.exit(1 if not args.fix else 1)

if __name__ == "__main__":
    main()