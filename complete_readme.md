# AI Sabotage Detection Tools

**Useful tools to remove AI sabotage from codebases and infrastructure**

---

## 🛡️ Overview

This repository contains specialized antivirus-style tools designed to detect and automatically fix common sabotage patterns that AI coding assistants may introduce into your projects. These tools scan codebases for problematic code patterns, infrastructure misconfigurations, and other issues that can compromise functionality and security.

## 📦 Tools Included

### 1. AI Sabotage Antivirus (ASAV)
**File:** `ai_sabotage_antivirus.py`

General-purpose scanner for detecting AI-introduced code sabotage across multiple programming languages.

**Features:**
- Detects bare except clauses, eval/exec usage, placeholders, and hardcoded paths
- Supports Python, JavaScript, TypeScript, Java, Go, Rust, C/C++, Ruby, PHP, and more
- Auto-fix capabilities with backup/restore functionality
- Quarantine system for safe rollbacks
- JSON reporting for CI/CD integration

### 2. Web Stack Edition (ASAV-WS)
**File:** `asav_ws.py`

Specialized scanner for web applications using NGINX + Gunicorn + Python stack.

**Features:**
- Python backend sabotage detection
- NGINX configuration vulnerability scanning
- Gunicorn misconfiguration detection
- Systemd service file validation
- Docker/deployment security checks

### 3. Web Stack Runtime Edition (ASAV-WS-Runtime)
**File:** `asav_ws_runtime.py`

Advanced scanner combining static analysis with live runtime testing.

**Features:**
- All ASAV-WS static detection capabilities
- Live HTTP probes to detect hidden vulnerabilities
- Remote host testing without local file access
- Open proxy detection through actual requests
- Directory listing enumeration
- Real-time infrastructure validation

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Anti-ai-sabotage-tools-for-removal-.git
cd Anti-ai-sabotage-tools-for-removal-

# Make scripts executable
chmod +x *.py
```

### Basic Usage

#### General Code Scanning
```bash
# Scan only (no changes)
python3 ai_sabotage_antivirus.py --path /path/to/your/project

# Scan and auto-fix with backup
python3 ai_sabotage_antivirus.py --path /path/to/your/project --fix --quarantine

# Generate JSON report
python3 ai_sabotage_antivirus.py --path /path/to/your/project --report-json report.json
```

#### Web Stack Scanning
```bash
# Scan web application infrastructure
python3 asav_ws.py --path /path/to/webapp --fix

# High severity issues only
python3 asav_ws.py --path /path/to/webapp --fix --severity-threshold high
```

#### Web Stack Runtime Scanning
```bash
# Static scan only
python3 asav_ws_runtime.py --path /srv/app

# Static scan + runtime probes (local)
python3 asav_ws_runtime.py --path /srv/app --url http://127.0.0.1 --fix --quarantine

# Probes only (remote host)
python3 asav_ws_runtime.py --url https://your.domain --json report.json
```

---

## 📋 Detection Capabilities

### Code-Level Issues
- **Bare Exception Handling:** `except:` without specific exception types
- **Silent Failures:** Exception swallowing with `pass`
- **Dangerous Functions:** Unsafe use of `eval()` and `exec()`
- **Placeholder Code:** TODO, XXX, and template placeholders left in production
- **Hardcoded Values:** Fixed paths, IPs, and configuration values
- **Insecure Randomness:** Random functions without fixed seeds

### Infrastructure Issues
- **NGINX Misconfigurations:** Open proxies, directory listings, overpermissive access
- **Gunicorn Problems:** Worker overflow, insecure configurations
- **Systemd Issues:** Insecure service definitions
- **Docker Security:** Unsafe build patterns, curl|bash installations
- **Debug Modes:** Production deployments with debug enabled

### Runtime Testing Features
- **Live Vulnerability Probes:** Real HTTP requests to detect active issues
- **Open Proxy Detection:** Tests for proxy misconfigurations through actual requests
- **Directory Listing Checks:** Verifies autoindex settings via live enumeration
- **Remote Host Scanning:** Test production sites without local file access
- **Combined Analysis:** Static code review + runtime behavior validation

---

## ⚙️ Configuration Options

### Severity Levels
- **Low:** Coding style and minor issues
- **Medium:** Potential functionality problems  
- **High:** Security vulnerabilities and major bugs
- **Critical:** Severe security risks requiring immediate attention

### Auto-Fix Features
- Automatic backup creation before modifications
- Unified diff patch generation for review
- Rollback capabilities via quarantine system
- Configurable fix application by severity level

### Exclusion Patterns
Default exclusions include:
- `.git/` directories
- `node_modules/`
- Virtual environments (`venv/`, `.venv/`)
- Quarantine directories

Custom exclusions can be added via `--exclude` flag.

---

## 📊 Reporting

### JSON Output Format
```json
{
  "results": [
    {
      "path": "example.py",
      "findings": [
        {
          "rule": "bare_except",
          "severity": "high", 
          "desc": "Bare 'except:' masks real errors"
        }
      ],
      "changed": true,
      "patch": "example.py.asav.patch"
    }
  ],
  "quarantine": ".asav_quarantine/20240118-143022"
}
```

### Patch Files
Generated `.asav.patch` files show exact changes made:
```diff
--- example.py
+++ example.py (fixed)
@@ -10,7 +10,7 @@
 def risky_function():
     try:
         dangerous_operation()
-    except:
+    except Exception:
         pass
```

---

## 🔧 Advanced Usage

### CI/CD Integration
```bash
# Exit code 0 = no issues, 1 = issues found, 2 = error
python3 ai_sabotage_antivirus.py --path . --severity-threshold high
if [ $? -eq 1 ]; then
    echo "High severity issues detected - failing build"
    exit 1
fi
```

### Restore from Quarantine
```bash
# Restore last quarantined version
python3 ai_sabotage_antivirus.py --restore-last
```

### Remote Testing
```bash
# Test live production site
python3 asav_ws_runtime.py --url https://yoursite.com --json security_report.json

# Combine static and runtime analysis  
python3 asav_ws_runtime.py --path /var/www/app --url http://localhost --fix
```

---

## 🛠️ Supported File Types

- **Python:** `.py`
- **JavaScript/TypeScript:** `.js`, `.ts`, `.tsx`, `.jsx`
- **Java:** `.java`
- **Go:** `.go`
- **Rust:** `.rs`
- **C/C++:** `.c`, `.cpp`, `.h`, `.hpp`
- **Ruby:** `.rb`
- **PHP:** `.php`
- **C#:** `.cs`
- **Configuration:** `.yaml`, `.yml`, `.toml`, `.ini`, `.conf`, `.json`
- **Scripts:** `.sh`, `.ps1`
- **Docker:** `Dockerfile`

---

## ⚠️ Important Notes

### Backup Strategy
Always use the `--quarantine` flag when applying fixes to ensure you can rollback changes if needed. The quarantine system preserves original files with timestamps for easy restoration.

### Review Fixes
While auto-fixes are designed to be safe, always review generated patches before deploying to production. Some fixes may require manual adjustment for your specific use case.

### False Positives
Some legitimate code patterns may trigger detections. Use severity thresholds and exclusion patterns to tune the scanner for your environment.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests to improve the detection capabilities and fix accuracy.

---

## 📄 License

This project is released under the MIT License. See LICENSE file for details.

---

## 🔍 Common Use Cases

1. **Post-AI Assistance Scanning:** Run after using AI coding assistants to detect introduced issues
2. **Code Review Automation:** Integrate into review processes to catch common problems
3. **Security Audits:** Identify potential vulnerabilities in codebases
4. **Infrastructure Validation:** Verify web stack configurations are secure
5. **CI/CD Quality Gates:** Prevent deployment of code with detected issues

---

*Last updated: [Current Date]*