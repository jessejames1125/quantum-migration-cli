# scanner/code_scanner.py
import subprocess
import yaml
import json
import os
import platform
import fnmatch
import logging

# Set up logging to both console and a file if desired.
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

def run_semgrep(target_path, rule_file="pqc_rules.yml"):
    if platform.system() == "Windows":
        print("Semgrep is not supported on Windows natively. Please run this under WSL or on Linux.")
        return {}
    
    cmd = ["semgrep", "--include", "*.py", "--config", rule_file, "--json", target_path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    
    except subprocess.CalledProcessError as e:
        print(f"Error running Semgrep: {e}")
        print("Semgrep output:", e.stdout, e.stderr)
        return {}
    
    except FileNotFoundError:
        print("Semgrep not found. Please install semgrep and ensure it is in your PATH.")
        return {}

def assess_risk(result):
    msg = result.get("extra", {}).get("message", "").lower().strip()
    if msg.startswith("insecure rsa key usage detected"):
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
    return "Low"

def should_include(file_name, include_patterns):
    for pattern in include_patterns:
        if fnmatch.fnmatch(file_name, pattern):
            return True
    return False

def should_exclude(dir_path, exclude_patterns):
    for pattern in exclude_patterns:
        if pattern in dir_path or fnmatch.fnmatch(dir_path, pattern):
            return True
    return False

def scan_codebase(root_path, config={}):
    """
    Recursively scans the root_path using the following configurable options from the 'config' dictionary:
      - include_patterns: list of glob patterns to include (default: ["*.py"])
      - exclude_directories: list of directory patterns to exclude (default: [])
      - dry_run: if True, only log files without full scanning.
      - verbose: if True, print detailed progress.
    """
    include_patterns = config.get("include_patterns", ["*.py"])
    exclude_dirs = config.get("exclude_directories", [])
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", True)
    
    findings = []
    
    if not os.path.exists(root_path):
        print(f"Error: The specified root path '{root_path}' does not exist.")
        return findings
    
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Exclude directories as per configuration.
        dirnames[:] = [d for d in dirnames if not should_exclude(os.path.join(dirpath, d), exclude_dirs)]
        if verbose:
            print(f"Scanning directory: {dirpath}")
        for file in filenames:
            if not should_include(file, include_patterns):
                continue
            file_path = os.path.join(dirpath, file)
            try:
                # Validate that file exists and is readable.
                if not os.access(file_path, os.R_OK):
                    if verbose:
                        print(f"Skipping unreadable file: {file_path}")
                    continue
                if dry_run:
                    print(f"[DRY RUN] Would scan: {file_path}")
                    continue
                # Run semgrep on the file.
                result = run_semgrep(file_path)
                for res in result.get("results", []):
                    findings.append({
                        "file": res.get("path", file_path),
                        "line": str(res.get("start", {}).get("line", "N/A")),
                        "message": res.get("extra", {}).get("message", "No message"),
                        "risk": assess_risk(res)
                    })
            except Exception as e:
                logging.error(f"Error scanning {file_path}: {e}")
                continue
    return findings

def load_config(config_file="config.yml"):
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
    # Return the 'scan' section if it exists, else return the full config.
    return config.get("scan", config)
