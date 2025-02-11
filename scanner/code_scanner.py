import subprocess
import json
import os
import platform

def run_semgrep(target_path, rule_file="pqc_rules.yml"):
    if platform.system() == "Windows":
        print("Semgrep is not supported on Windows natively. Please run this under WSL or on Linux.")
        return {}
    
    # Restrict to Python files only.
    cmd = ["semgrep", "--include", "*.py", "--config", rule_file, "--json", target_path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    
    except subprocess.CalledProcessError as e:
        print(f"Error running Semgrep: {e}")
        print("Semgrep output:", e.stdout, e.stderr)  # Print error details for debugging
        return {}
    
    except FileNotFoundError:
        print("Semgrep not found. Please install semgrep and ensure it is in your PATH.")
        return {}

def assess_risk(result):
    # Retrieve and normalize the message from semgrep.
    msg = result.get("extra", {}).get("message", "").lower().strip()

    # Only flag messages that explicitly indicate insecure usage.
    # If the message doesn't start with one of these known patterns, default to "Low".
    if msg.startswith("insecure rsa key usage detected"):
        # If the message also mentions a secure alternative, mark as Low.
        if (">=3072" in msg) or ("kyber" in msg):
            return "Low"
        return "High"
    elif msg.startswith("insecure use of md5 detected"):
        return "High"
    elif msg.startswith("insecure use of sha-1 detected"):
        return "High"
    elif msg.startswith("insecure use of ecdsa detected"):
        return "High"
    elif msg.startswith("insecure use of triple des detected") or ("3des" in msg and "insecure" in msg):
        return "Medium"
    elif msg.startswith("insecure use of diffie") or ("diffie" in msg and "insecure" in msg):
        return "Low"
    elif msg.startswith("insecure hmac with md5 detected"):
        return "High"
    # If the message does not match any known insecure pattern, treat it as Low risk.
    return "Low"

def scan_codebase(path):
    print(f"Scanning code in {path} for outdated cryptography...")
    if not os.path.exists(path):
        print(f"Path not found: {path}")
        return []
    
    results = run_semgrep(path)
    findings = []

    for result in results.get("results", []):
        findings.append({
            "file": result.get("path", "Unknown"),
            "line": str(result.get("start", {}).get("line", "N/A")),
            "message": result.get("extra", {}).get("message", "No message"),
            "risk": assess_risk(result)
        })
    
    return findings
