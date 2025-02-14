# tests/test_scan.py
import os
import tempfile
import pytest
from scanner import code_scanner

def test_scan_nonexistent_directory():
    # Should return an empty list and print an error message.
    findings = code_scanner.scan_codebase("/nonexistent/directory")
    assert findings == []

def test_dry_run_mode(tmp_path):
    # Create a temporary directory with a sample file.
    d = tmp_path / "testdir"
    d.mkdir()
    file = d / "vulnerable.py"
    file.write_text("import hashlib\nhashlib.md5(b'test')")
    
    # Create a config dict with dry_run enabled.
    config = {
        "include_patterns": ["*.py"],
        "exclude_directories": [],
        "dry_run": True,
        "verbose": False,
        "anonymize": False
    }
    findings = code_scanner.scan_codebase(str(d), config=config)
    # In dry_run mode, findings should be empty.
    assert findings == []

if __name__ == "__main__":
    pytest.main()
