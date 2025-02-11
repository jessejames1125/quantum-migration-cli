import os
import re

def determine_config_risk(alg):
    high = ["RSA", "ECDSA", "SHA-1", "MD5"]
    medium = ["3DES", "Diffie"]
    low = ["AES"]
    if alg.upper() in high:
        return "High"
    elif alg.upper() in medium:
        return "Medium"
    else:
        return "Low"

def scan_file(file_path):
    # Do not scan our own rules file
    if os.path.basename(file_path) in ["pqc_rules.yml"]:
        return []
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # For each algorithm, only flag if no safe indicator is found.
        patterns = {
            "RSA": (r"\bRSA\b", ["hybrid RSA+Kyber", ">=3072"]),
            "ECDSA": (r"\bECDSA\b", []),
            "MD5": (r"\bMD5\b", ["SHA-256", "SHA-3"]),
            "SHA-1": (r"\bSHA-1\b", ["SHA-256", "SHA-3"]),
            "AES": (r"\bAES\b", []),
            "3DES": (r"\b3DES\b", []),
            "Diffie": (r"\bDiffie[- ]?Hellman\b", []),
        }
        for alg, (pat, safe_indicators) in patterns.items():
            if re.search(pat, content, re.IGNORECASE):
                safe_found = any(safe in content for safe in safe_indicators)
                if not safe_found:
                    findings.append({
                        "file": file_path,
                        "line": "N/A",
                        "message": f"Found reference to {alg} in config.",
                        "risk": determine_config_risk(alg)
                    })
    except Exception as e:
        findings.append({
            "file": file_path,
            "line": "N/A",
            "message": f"Error: {e}",
            "risk": "Unknown"
        })
    return findings

def scan_config_dir(path):
    print(f"Scanning configuration files in {path} ...")
    findings = []
    config_exts = {".yml", ".yaml", ".json", ".ini", ".conf"}
    for root, _, files in os.walk(path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in config_exts:
                file_path = os.path.join(root, file)
                findings.extend(scan_file(file_path))
    return findings
