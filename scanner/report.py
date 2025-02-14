# report.py
from rich.console import Console
from rich.table import Table
import os
from jinja2 import Template

# Attempt to import WeasyPrint for PDF generation.
try:
    from weasyprint import HTML
    weasyprint_available = True
except ImportError:
    weasyprint_available = False

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

def generate_rich_report(findings):
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

def generate_html_report(findings, output_file="report.html"):
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Quantum Migration Audit Report</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #dddddd; padding: 8px; text-align: left; }
        th { background-color: #4f46e5; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
      </style>
    </head>
    <body>
      <h1>Quantum Migration Audit Report</h1>
      <table>
        <tr>
          <th>Location/File</th>
          <th>Line/Component</th>
          <th>Message</th>
          <th>Risk</th>
          <th>Recommendation</th>
        </tr>
        {% for finding in findings %}
        <tr>
          <td>{{ finding.file }}</td>
          <td>{{ finding.line }}</td>
          <td>{{ finding.message }}</td>
          <td>{{ finding.risk }}</td>
          <td>{{ finding.recommendation }}</td>
        </tr>
        {% endfor %}
      </table>
    </body>
    </html>
    """
    # Add recommendations to each finding.
    for finding in findings:
        finding["recommendation"] = get_recommendation(finding)
    template = Template(template_str)
    rendered_html = template.render(findings=findings)
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(rendered_html)
    print(f"HTML report generated: {output_file}")
    return output_file

def generate_pdf_report(html_file, output_file="report.pdf"):
    if not weasyprint_available:
        print("WeasyPrint is not installed. Cannot generate PDF report.")
        return None
    HTML(html_file).write_pdf(output_file)
    print(f"PDF report generated: {output_file}")
    return output_file

def display_report(findings, output_format="rich"):
    if output_format == "rich":
        generate_rich_report(findings)
    elif output_format == "html":
        html_file = generate_html_report(findings)
        print("Open the HTML file in a browser for a polished view.")
    elif output_format == "pdf":
        html_file = generate_html_report(findings, output_file="temp_report.html")
        pdf_file = generate_pdf_report(html_file)
        if pdf_file:
            print("PDF report generated successfully.")
    else:
        print("Unsupported output format. Defaulting to rich output.")
        generate_rich_report(findings)
