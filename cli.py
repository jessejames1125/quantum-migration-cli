#!/usr/bin/env python3
import click
import json
from scanner import code_scanner, tls_scanner, config_scanner, report
from data_parser import scan_data_file

def interactive_config():
    """Interactively generate a config file."""
    click.echo("Interactive Configuration Wizard for Quantum Migration CLI Scanner")
    scan_root = click.prompt("Enter the root directory to scan", default=".")
    include = click.prompt("Enter file patterns to include (comma-separated)", default="*.py,*.js,*.json,*.cfg,*.ini,*.yml")
    exclude = click.prompt("Enter directories to exclude (comma-separated)", default=".git,node_modules,/proc,/sys,C:\\Windows")
    dry_run = click.confirm("Enable dry-run mode (only log files without scanning)?", default=False)
    verbose = click.confirm("Enable verbose mode?", default=True)
    anonymize = click.confirm("Anonymize file paths in the report?", default=False)
    
    config_data = {
        "scan_root": scan_root,
        "include_patterns": [pattern.strip() for pattern in include.split(",")],
        "exclude_directories": [pattern.strip() for pattern in exclude.split(",")],
        "dry_run": dry_run,
        "verbose": verbose,
        "anonymize": anonymize
    }
    filename = click.prompt("Enter the config file name to save", default="config.yml")
    try:
        import yaml
        with open(filename, "w") as f:
            yaml.dump({"scan": config_data}, f)
        click.echo(f"Configuration saved to {filename}")
    except Exception as e:
        click.echo(f"Error saving configuration: {e}")

@click.group()
def cli():
    """Quantum Migration CLI Tool: Audit Your Cryptography."""
    pass

@cli.command(name="configure")
def configure():
    """Interactively generate a configuration file."""
    interactive_config()

@cli.command(name="scan_code")
@click.option('--path', default='.', help='Directory path to recursively scan for vulnerable code')
@click.option('--output-format', default='rich', type=click.Choice(['rich', 'html', 'pdf']), help='Output format for the report')
def scan_code(path, output_format):
    """Scan the codebase for vulnerable cryptography usage."""
    click.echo(f"Running code scanner on directory: {path}")
    results = code_scanner.scan_codebase(path)
    report.display_report(results, output_format)

@cli.command(name="scan_config")
@click.option('--path', default='.', help='Directory path to recursively scan for configuration files')
@click.option('--output-format', default='rich', type=click.Choice(['rich', 'html', 'pdf']), help='Output format for the report')
def scan_config(path, output_format):
    """Scan configuration files for weak crypto settings."""
    click.echo(f"Running config scanner on directory: {path}")
    results = config_scanner.scan_config_dir(path)
    report.display_report(results, output_format)

@cli.command(name="scan_tls")
@click.option('--host', default=None, help='Single hostname for TLS scan')
@click.option('--host-file', default=None, help='File with one hostname per line for TLS scanning')
@click.option('--output-format', default='rich', type=click.Choice(['rich', 'html', 'pdf']), help='Output format for the report')
def scan_tls(host, host_file, output_format):
    """Scan TLS certificates for vulnerabilities."""
    hosts = []
    if host_file:
        try:
            with open(host_file, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
        except Exception as e:
            click.echo(f"Error reading host file: {e}")
            return
    elif host:
        hosts = [host]
    else:
        click.echo("Provide either --host or --host-file")
        return

    all_results = []
    for h in hosts:
        click.echo(f"Running TLS scanner for host: {h}")
        results = tls_scanner.scan_tls_certificate(h)
        all_results.extend(results)
    report.display_report(all_results, output_format)

@cli.command(name="scan_all")
@click.option('--config-file', default='config.yml', help='Path to configuration file')
@click.option('--host', default=None, help='Single hostname for TLS scan')
@click.option('--host-file', default=None, help='File with one hostname per line for TLS scanning')
@click.option('--output-format', default='rich', type=click.Choice(['rich', 'html', 'pdf']), help='Output format for the report')
def scan_all(config_file, host, host_file, output_format):
    """Run all scanners and generate a comprehensive report."""
    click.echo("Loading configuration...")
    try:
        import yaml
        with open(config_file, "r") as f:
            full_config = yaml.safe_load(f)
        config = full_config.get("scan", {})
    except Exception as e:
        click.echo(f"Configuration error: {e}")
        return

    scan_root = config.get("scan_root", ".")
    click.echo(f"Scanning files under: {scan_root}")
    code_findings = code_scanner.scan_codebase(scan_root, config=config)
    config_findings = config_scanner.scan_config_dir(scan_root)

    hosts = []
    if host_file:
        try:
            with open(host_file, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
        except Exception as e:
            click.echo(f"Error reading host file: {e}")
    elif host:
        hosts = [host]

    tls_findings = []
    for h in hosts:
        click.echo(f"Running TLS scanner for host: {h}")
        tls_findings.extend(tls_scanner.scan_tls_certificate(h))

    combined = code_findings + config_findings + tls_findings
    report.display_report(combined, output_format)

@cli.command(name="scan_data")
@click.option('--data-file', required=True, help='Path to a CSV, JSON, or XML data export to scan')
@click.option('--output-format', default='rich', type=click.Choice(['rich', 'html', 'pdf']), help='Output format for the report')
def scan_data(data_file, output_format):
    """Scan a data file (CSV, JSON, XML) for cryptographic vulnerabilities.
    (This is a placeholder for future extension.)"""
    click.echo(f"Scanning data file: {data_file}")
    findings = scan_data_file(data_file)
    report.display_report(findings, output_format)

if __name__ == '__main__':
    cli()
