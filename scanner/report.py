from rich.console import Console
from rich.table import Table

def get_recommendation(finding):
    msg = finding.get("message", "").lower()
    recs = []
    if "md5" in msg:
        recs.append("Replace MD5 with SHA-2 or SHA-3 and use secure HMAC.")
    if "sha-1" in msg:
        recs.append("Upgrade to SHA-2 or SHA-3 to prevent collision attacks.")
    if "rsa" in msg:
        recs.append("Replace with hybrid RSA+Kyber or use RSA with at least 3072-bit keys.")
    if "ecdsa" in msg:
        recs.append("Migrate to PQC alternatives such as Dilithium or Falcon for signatures.")
    if "3des" in msg:
        recs.append("Replace 3DES with AES-256 or a modern symmetric cipher.")
    if "diffie" in msg:
        recs.append("Switch to a Kyber-based key exchange.")
    if "hmac" in msg:
        recs.append("Replace HMAC with MD5 with one using SHA-2 or SHA-3.")
    if "hardcoded" in msg:
        recs.append("Remove hardcoded keys and implement secure key management.")
    if not recs:
        recs.append("Review the finding and develop a full PQC migration roadmap.")
    return " | ".join(recs)

def display_report(findings):
    console = Console()
    table = Table(title="Quantum Migration Audit Report")
    table.add_column("Location/File", style="cyan")
    table.add_column("Line/Component", justify="center")
    table.add_column("Message", style="magenta")
    table.add_column("Risk", style="red")
    table.add_column("Recommendation", style="green")

    if not findings:
        console.print("No issues found.")
        return

    for finding in findings:
        loc = finding.get("file", finding.get("component", "Unknown"))
        line = str(finding.get("line", "N/A"))
        msg = finding.get("message", "No message")
        risk = finding.get("risk", "Unknown")
        recommendation = get_recommendation(finding)
        table.add_row(loc, line, msg, risk, recommendation)
    console.print(table)
