Quantum Migration CLI Tool
============================

Overview:
---------
Quantum Migration is an AI-powered automated post-quantum cryptography migration platform.
This CLI tool scans an organization’s file system for vulnerable cryptographic usage. It
recursively traverses directories—using configurable include/exclude patterns—to detect
insecure implementations in code, configuration files, and TLS certificates. The tool
generates a professional report with detailed findings and actionable recommendations.

Directory Structure:
----------------------
quantum_migration_cli/
├── cli.py                   # Main CLI entry point
├── config.yml               # Combined configuration (encryption, logging, scan settings)
├── data_parser.py           # Future module for scanning CSV/JSON/XML exports
├── pqc_rules.yml            # Semgrep rules for detecting insecure cryptography
├── README.txt               # This file
├── requirements.txt         # Python dependencies
└── scanner/                 # Scanner modules
    ├── __init__.py
    ├── code_scanner.py      # Recursively scans files using configuration settings
    ├── config_scanner.py    # Scans configuration files for weak crypto settings
    ├── report.py            # Generates polished audit reports (Rich/HTML/PDF)
    └── tls_scanner.py       # Scans TLS certificates for vulnerabilities

Setup:
------
1. Clone the repository:
   git clone https://github.com/jessejames1125/quantum-migration-cli.git

2. Navigate to the project directory:
   cd quantum-migration-cli

3. Install dependencies:
   pip install -r requirements.txt

   (Ensure that requirements.txt includes:
     click
     rich
     pyOpenSSL
     semgrep
     rsa
     pyyaml
     jinja2
     weasyprint   [Optional: for PDF generation]
     )

4. Review and update the configuration:
   - Open config.yml in the root folder.
   - Set "scan.scan_root" to the directory you wish to scan.
   - Adjust include_patterns and exclude_directories as needed.

Usage:
------
The tool provides multiple commands:

1. scan_code:
   Scans the codebase for vulnerable cryptography usage.
   Usage:
       python3 cli.py scan_code --path <directory_path> [--output-format rich|html|pdf]

2. scan_config:
   Scans configuration files for weak cryptography.
   Usage:
       python3 cli.py scan_config --path <directory_path> [--output-format rich|html|pdf]

3. scan_tls:
   Scans TLS certificates for vulnerabilities.
   Usage:
       python3 cli.py scan_tls --host <hostname>
       OR
       python3 cli.py scan_tls --host-file <file_with_hostnames> [--output-format rich|html|pdf]

4. scan_all:
   Loads configuration from config.yml and runs all scanners.
   Usage:
       python3 cli.py scan_all --config-file config.yml [--host <hostname> or --host-file <file>] [--output-format rich|html|pdf]

5. scan_data:
   (Future Extension) Scans a CSV/JSON/XML file for cryptographic vulnerabilities.
   Usage:
       python3 cli.py scan_data --data-file <path_to_file> [--output-format rich|html|pdf]

Notes:
------
- Use the dry_run option in config.yml to list files without full analysis.
- The tool operates in read-only mode and does not modify any files.
- Detailed logging and robust error handling ensure the scan continues even if some files cannot be read.

Reporting:
----------
Reports are generated in one of three formats:
  - Rich (terminal table via Rich)
  - HTML (polished web view using Jinja2)
  - PDF (converted from HTML using WeasyPrint)
Choose the output format using the --output-format option.

Contributing:
-------------
Contributions are welcome. Please ensure any changes are thoroughly tested and documented.
For issues or pull requests, use the GitHub repository.

License:
--------
[Specify your license here]

Contact:
--------
For support, contact: info@quantummigration.io
