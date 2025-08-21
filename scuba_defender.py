#!/usr/bin/env python3
"""
SCUBA AI DEFENDER - Unified Anti-Interference Tool
==================================================
Combines all AI sabotage detection methods into one easy-to-use script.

Features:
- Static code analysis (Python, JS, configs, Docker)
- Real-time diff analysis
- Web stack probes (NGINX, Gunicorn, Flask)
- Auto-fix with quarantine backup
- Comprehensive reporting
- One-command protection

Quick Usage:
    python scuba_defender.py scan /path/to/project
    python scuba_defender.py fix /path/to/project --backup
    python scuba_defender.py diff original.py modified.py
    python scuba_defender.py probe http://localhost:8000
    python scuba_defender.py watch /path/to/project
"""

import os
import sys
import re
import json
import time
import shutil
import socket
import ssl
import hashlib
import difflib
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Callable, Pattern
from urllib.parse import urlparse

# Try to import optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import pyperclip
    HAS_CLIPBOARD = True
except ImportError:
    HAS_CLIPBOARD = False

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

VERSION = "1.0.0"
QUARANTINE_DIR = ".scuba_quarantine"
SUPPORTED_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".c", ".cpp", 
    ".h", ".hpp", ".rb", ".php", ".cs", ".kt", ".m", ".swift", ".scala", 
    ".sh", ".ps1", ".yaml", ".yml", ".toml", ".ini", ".conf", ".json", 
    ".env", ".dockerfile", "Dockerfile"
}

# ============================================================================
# DETECTION RULES AND PATTERNS
# ============================================================================

@dataclass
class Rule:
    key: str
    description: str
    pattern: Pattern
    severity: str
    category: str
    fixer: Optional[Callable[[str], str]] = None

# Auto-fix functions
def _fix_bare_except(text: str) -> str:
    return re.sub(r"except\s*:", "except Exception:", text)

def _fix_silent_pass(text: str) -> str:
    return re.sub(r"except\s+([^\n:]+)?:\s*pass", 
                  r"except \1 as e:\n    # SCUBA: Prevented silent error suppression\n    raise", text)

def _fix_eval_exec(text: str) -> str:
    return re.sub(r"\b(eval|exec)\(", r"# SCUBA-BLOCKED-\1(", text)

def _fix_debug_mode(text: str) -> str:
    return re.sub(r"app\.run\(.*debug\s*=\s*True.*\)", "app.run(debug=False)", text)

def _fix_hardcoded_paths(text: str) -> str:
    text = re.sub(r"(?<![A-Za-z0-9_])/tmp/", "os.getenv('TMPDIR', '/tmp/')/", text)
    text = re.sub(r"127\.0\.0\.1", "os.getenv('HOST','127.0.0.1')", text)
    return text

def _fix_unsafe_shell(text: str) -> str:
    text = re.sub(r"(curl\s+[^\n]+?\|\s*(bash|sh))", r"# SCUBA-BLOCKED: \1", text, flags=re.IGNORECASE)
    text = re.sub(r"(iwr\s+[^\n]+?\|\s*iex)", r"# SCUBA-BLOCKED: \1", text, flags=re.IGNORECASE)
    return text

def _fix_open_proxy(text: str) -> str:
    return re.sub(r"proxy_pass\s+http://\$\w+;", "# SCUBA: Unsafe proxy_pass disabled", text)

def _fix_autoindex(text: str) -> str:
    return re.sub(r"autoindex\s+on;", "autoindex off;", text)

# Comprehensive detection rules
DETECTION_RULES: List[Rule] = [
    # High-risk sabotage patterns
    Rule("bare_except", "Bare 'except:' masks errors", 
         re.compile(r"except\s*:"), "critical", "error_handling", _fix_bare_except),
    
    Rule("silent_pass", "Exception swallowed with 'pass'", 
         re.compile(r"except[^\n]*\bpass\b"), "critical", "error_handling", _fix_silent_pass),
    
    Rule("eval_exec", "Dangerous eval/exec usage", 
         re.compile(r"\b(eval|exec)\("), "critical", "code_injection", _fix_eval_exec),
    
    Rule("debug_mode", "Debug mode enabled in production", 
         re.compile(r"app\.run\(.*debug\s*=\s*True.*\)"), "high", "security", _fix_debug_mode),
    
    Rule("unsafe_shell", "Dangerous shell pipeline", 
         re.compile(r"(curl\s+[^\n]+?\|\s*(bash|sh))|(iwr\s+[^\n]+?\|\s*iex)", re.IGNORECASE), 
         "critical", "shell_injection", _fix_unsafe_shell),
    
    # Unauthorized additions
    Rule("unauthorized_imports", "Suspicious safety/monitoring imports", 
         re.compile(r"import\s+(logging|warnings|safety|security|compliance|validate)"), 
         "high", "unauthorized_addition"),
    
    Rule("hidden_validators", "Hidden validation functions", 
         re.compile(r"def\s+(?:validate_|check_|sanitize_|guard_|filter_)\w+\s*\("), 
         "high", "unauthorized_addition"),
    
    Rule("safety_assertions", "Unauthorized safety assertions", 
         re.compile(r"assert\s+.*(?:safe|valid|approved|compliant)"), 
         "medium", "unauthorized_addition"),
    
    # Configuration sabotage
    Rule("hardcoded_paths", "Hardcoded paths/hosts", 
         re.compile(r"(/tmp/|127\.0\.0\.1)"), "medium", "hardcoded_config", _fix_hardcoded_paths),
    
    Rule("open_proxy", "NGINX open proxy configuration", 
         re.compile(r"proxy_pass\s+http://\$\w+;"), "critical", "web_config", _fix_open_proxy),
    
    Rule("autoindex_on", "Directory listing enabled", 
         re.compile(r"autoindex\s+on;"), "medium", "web_config", _fix_autoindex),
    
    Rule("excessive_workers", "Suspicious worker count", 
         re.compile(r"workers\s*=\s*[0-9]{3,}"), "medium", "web_config"),
    
    # Stealth modifications
    Rule("stealth_comments", "Stealth modification comments", 
         re.compile(r"#.*(?:improved|optimized|refactored|cleaned|for clarity|for safety|best practice)", re.IGNORECASE), 
         "low", "stealth_modification"),
    
    Rule("safety_theater", "Safety theater comments", 
         re.compile(r"#.*(?:enterprise ready|production grade|security compliant)", re.IGNORECASE), 
         "low", "safety_theater"),
    
    # Dependency tampering
    Rule("version_pinning", "Suspicious version constraints", 
         re.compile(r"version\s*[=><!]+\s*[\d.]+(?:\.\*)?"), "medium", "dependency_tampering"),
    
    Rule("safe_imports", "Renamed 'safe' imports", 
         re.compile(r"import\s+\w+\s+as\s+\w+_(?:safe|secure|validated)"), "medium", "dependency_tampering"),
    
    # Naming sabotage
    Rule("deprecated_naming", "Suspicious deprecation naming", 
         re.compile(r"(?:old_|legacy_|unsafe_|deprecated_)\w+"), "medium", "naming_sabotage"),
    
    Rule("private_renaming", "Unnecessary private renaming", 
         re.compile(r"_(?:internal|private|restricted)(?=\W)"), "low", "naming_sabotage"),
]

# ============================================================================
# CORE ANALYSIS CLASSES
# ============================================================================

class ScanResult:
    def __init__(self):
        self.findings = []
        self.files_scanned = 0
        self.files_with_issues = 0
        self.total_issues = 0
        self.risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        self.categories = {}
        self.quarantine_path = None

class FileAnalyzer:
    def __init__(self):
        self.rules = DETECTION_RULES
    
    def analyze_file(self, file_path: Path, apply_fixes: bool = False) -> Dict[str, Any]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return {"path": str(file_path), "error": str(e), "findings": []}
        
        original_content = content
        findings = []
        
        for rule in self.rules:
            matches = list(rule.pattern.finditer(content))
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    "rule": rule.key,
                    "description": rule.description,
                    "severity": rule.severity,
                    "category": rule.category,
                    "line": line_num,
                    "match": match.group(0),
                    "position": [match.start(), match.end()]
                })
                
                if apply_fixes and rule.fixer:
                    content = rule.fixer(content)
        
        result = {
            "path": str(file_path),
            "findings": findings,
            "changed": content != original_content
        }
        
        if apply_fixes and result["changed"]:
            result["original"] = original_content
            result["fixed"] = content
        
        return result

class DiffAnalyzer:
    def __init__(self):
        self.analyzer = FileAnalyzer()
    
    def compare_content(self, original: str, modified: str) -> Dict[str, Any]:
        diff_lines = list(difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile='original',
            tofile='modified',
            n=3
        ))
        
        # Analyze what was added/removed
        added_lines = []
        removed_lines = []
        
        for line in diff_lines:
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:].strip())
            elif line.startswith('-') and not line.startswith('---'):
                removed_lines.append(line[1:].strip())
        
        # Check added content for sabotage patterns
        added_content = '\n'.join(added_lines)
        sabotage_found = []
        
        for rule in DETECTION_RULES:
            matches = rule.pattern.findall(added_content)
            if matches:
                sabotage_found.append({
                    "rule": rule.key,
                    "description": rule.description,
                    "severity": rule.severity,
                    "category": rule.category,
                    "matches": matches
                })
        
        # Check for removed functionality
        removed_content = '\n'.join(removed_lines)
        bypass_keywords = ["bypass", "override", "unrestricted", "direct", "raw", "unfiltered"]
        removed_functionality = []
        
        for keyword in bypass_keywords:
            if re.search(keyword, removed_content, re.IGNORECASE):
                removed_functionality.append({
                    "keyword": keyword,
                    "lines": [line for line in removed_lines if keyword.lower() in line.lower()]
                })
        
        return {
            "added_lines": len(added_lines),
            "removed_lines": len(removed_lines),
            "sabotage_patterns": sabotage_found,
            "removed_functionality": removed_functionality,
            "diff": ''.join(diff_lines),
            "risk_level": self._calculate_diff_risk(sabotage_found, removed_functionality)
        }
    
    def _calculate_diff_risk(self, sabotage: List, removed: List) -> str:
        critical_count = sum(1 for s in sabotage if s["severity"] == "critical")
        high_count = sum(1 for s in sabotage if s["severity"] == "high")
        
        if critical_count > 0 or len(removed) > 0:
            return "critical"
        elif high_count > 1:
            return "high"
        elif high_count > 0 or len(sabotage) > 2:
            return "medium"
        else:
            return "low"

class WebProber:
    def __init__(self):
        self.timeout = 5
    
    def probe_target(self, base_url: str) -> Dict[str, Any]:
        parsed = urlparse(base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_tls = parsed.scheme == "https"
        
        results = {
            "target": base_url,
            "timestamp": datetime.now().isoformat(),
            "probes": []
        }
        
        # HTTP Method tests
        results["probes"].append(self._test_trace_method(host, port, is_tls, parsed.path or '/'))
        results["probes"].append(self._test_absolute_uri(host, port, is_tls))
        
        # Directory listing tests
        results["probes"].append(self._test_directory_listing(host, port, is_tls))
        
        # Sensitive endpoint tests
        results["probes"].append(self._test_sensitive_endpoints(host, port, is_tls))
        
        # Server info
        if HAS_REQUESTS:
            results["probes"].append(self._test_server_headers(base_url))
        
        return results
    
    def _raw_http_request(self, host: str, port: int, is_tls: bool, 
                         request_line: str, headers: Dict[str, str], body: bytes = b"") -> str:
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            if is_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            request = request_line + "\r\n"
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
            request += "\r\n"
            
            sock.sendall(request.encode('utf-8') + body)
            sock.settimeout(self.timeout)
            
            response_chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_chunks.append(chunk)
                except socket.timeout:
                    break
            
            sock.close()
            return b''.join(response_chunks).decode('latin1', errors='ignore')
        
        except Exception as e:
            return f"ERROR: {e}"
    
    def _test_trace_method(self, host: str, port: int, is_tls: bool, path: str) -> Dict[str, Any]:
        response = self._raw_http_request(host, port, is_tls, f"TRACE {path} HTTP/1.1", {"Host": host})
        return {
            "name": "TRACE Method Test",
            "vulnerable": "TRACE" in response and "200" in response.split('\n')[0],
            "response_snippet": response[:300]
        }
    
    def _test_absolute_uri(self, host: str, port: int, is_tls: bool) -> Dict[str, Any]:
        response = self._raw_http_request(host, port, is_tls, "GET http://evil.com/ HTTP/1.1", {"Host": host})
        return {
            "name": "Absolute URI Test",
            "vulnerable": not ("400" in response or "404" in response),
            "response_snippet": response[:300]
        }
    
    def _test_directory_listing(self, host: str, port: int, is_tls: bool) -> Dict[str, Any]:
        test_paths = ["/", "/static/", "/public/", "/files/", "/.well-known/"]
        results = []
        
        for path in test_paths:
            response = self._raw_http_request(host, port, is_tls, f"GET {path} HTTP/1.1", {"Host": host})
            listing_detected = any(indicator in response.lower() for indicator in [
                "index of", "directory listing", "autoindex", "<title>index of"
            ])
            results.append({
                "path": path,
                "listing_enabled": listing_detected,
                "response_snippet": response[:200]
            })
        
        return {
            "name": "Directory Listing Test",
            "results": results,
            "vulnerable_paths": [r["path"] for r in results if r["listing_enabled"]]
        }
    
    def _test_sensitive_endpoints(self, host: str, port: int, is_tls: bool) -> Dict[str, Any]:
        sensitive_paths = [
            "/.git/HEAD", "/.env", "/server-status", "/nginx_status", 
            "/debug", "/__debug__", "/.svn/", "/backup.sql", "/config.php"
        ]
        results = []
        
        for path in sensitive_paths:
            response = self._raw_http_request(host, port, is_tls, f"GET {path} HTTP/1.1", {"Host": host})
            exposed = not ("404" in response or "403" in response or "500" in response)
            if exposed:
                # Additional checks for specific indicators
                if path == "/.git/HEAD":
                    exposed = "ref: refs/heads" in response
                elif path == "/.env":
                    exposed = any(indicator in response.lower() for indicator in ["database", "secret", "api_key", "password"])
                elif "status" in path:
                    exposed = any(indicator in response for indicator in ["Active connections", "server_status", "nginx"])
            
            results.append({
                "path": path,
                "exposed": exposed,
                "response_snippet": response[:200]
            })
        
        return {
            "name": "Sensitive Endpoints Test",
            "results": results,
            "exposed_endpoints": [r["path"] for r in results if r["exposed"]]
        }
    
    def _test_server_headers(self, url: str) -> Dict[str, Any]:
        try:
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            server_header = response.headers.get("Server", "Unknown")
            
            # Check for information disclosure
            risky_headers = {}
            for header, value in response.headers.items():
                if any(risky in header.lower() for risky in ["server", "x-powered-by", "x-aspnet-version"]):
                    risky_headers[header] = value
            
            return {
                "name": "Server Information Disclosure",
                "server": server_header,
                "risky_headers": risky_headers,
                "information_disclosed": len(risky_headers) > 0
            }
        except Exception as e:
            return {
                "name": "Server Information Disclosure",
                "error": str(e)
            }

# ============================================================================
# MAIN SCUBA DEFENDER CLASS
# ============================================================================

class ScubaDefender:
    def __init__(self):
        self.file_analyzer = FileAnalyzer()
        self.diff_analyzer = DiffAnalyzer()
        self.web_prober = WebProber()
        self.quarantine_root = Path(QUARANTINE_DIR)
    
    def scan_path(self, target_path: str, recursive: bool = True) -> ScanResult:
        """Scan files for AI interference patterns"""
        path = Path(target_path)
        result = ScanResult()
        
        if path.is_file():
            files_to_scan = [path] if self._is_supported_file(path) else []
        else:
            files_to_scan = self._collect_files(path, recursive)
        
        result.files_scanned = len(files_to_scan)
        
        for file_path in files_to_scan:
            analysis = self.file_analyzer.analyze_file(file_path)
            
            if "error" in analysis:
                continue
            
            if analysis["findings"]:
                result.files_with_issues += 1
                result.total_issues += len(analysis["findings"])
                
                for finding in analysis["findings"]:
                    result.risk_counts[finding["severity"]] += 1
                    category = finding["category"]
                    if category not in result.categories:
                        result.categories[category] = 0
                    result.categories[category] += 1
                
                result.findings.append(analysis)
        
        return result
    
    def fix_issues(self, target_path: str, backup: bool = True, 
                   severity_threshold: str = "medium") -> Dict[str, Any]:
        """Fix detected issues with optional backup"""
        path = Path(target_path)
        
        if path.is_file():
            files_to_fix = [path] if self._is_supported_file(path) else []
     