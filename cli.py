import click
from scanner import code_scanner, tls_scanner, config_scanner, report

@click.group()
def cli():
    """Quantum Migration CLI Tool: Audit Your Cryptography."""
    pass

@cli.command(name="scan_code")
@click.option('--path', default='.', help='Directory path to recursively scan for vulnerable code')
def scan_code(path):
    """Scan the codebase for vulnerable cryptography usage."""
    click.echo(f"Running code scanner on directory: {path}")
    results = code_scanner.scan_codebase(path)
    report.display_report(results)

@cli.command(name="scan_config")
@click.option('--path', default='.', help='Directory path to recursively scan for configuration files')
def scan_config(path):
    """Scan configuration files for weak crypto settings."""
    click.echo(f"Running config scanner on directory: {path}")
    results = config_scanner.scan_config_dir(path)
    report.display_report(results)

@cli.command(name="scan_tls")
@click.option('--host', default=None, help='Single hostname for TLS scan')
@click.option('--host-file', default=None, help='File with one hostname per line for TLS scanning')
def scan_tls(host, host_file):
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
    report.display_report(all_results)

@cli.command(name="scan_all")
@click.option('--code-path', default='.', help='Directory path for code scan')
@click.option('--config-path', default='.', help='Directory path for config scan')
@click.option('--host', default=None, help='Single hostname for TLS scan')
@click.option('--host-file', default=None, help='File with one hostname per line for TLS scanning')
def scan_all(code_path, config_path, host, host_file):
    """Run all scanners and generate a comprehensive report."""
    click.echo("Running all scanners...")
    code_findings = code_scanner.scan_codebase(code_path)
    config_findings = config_scanner.scan_config_dir(config_path)

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
    report.display_report(combined)

if __name__ == '__main__':
    cli()
