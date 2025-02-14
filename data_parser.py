# data_parser.py
import csv
import json
import xml.etree.ElementTree as ET

def parse_csv(file_path):
    """Reads a CSV file and returns a list of dictionaries."""
    findings = []
    try:
        with open(file_path, mode='r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                findings.append(row)
    except Exception as e:
        findings.append({"error": f"CSV parsing error: {e}"})
    return findings

def parse_json(file_path):
    """Reads a JSON file and returns its content (list or dict)."""
    findings = []
    try:
        with open(file_path, mode='r', encoding='utf-8') as jsonfile:
            data = json.load(jsonfile)
            # If data is a list, assume each element is a finding.
            if isinstance(data, list):
                findings.extend(data)
            else:
                findings.append(data)
    except Exception as e:
        findings.append({"error": f"JSON parsing error: {e}"})
    return findings

def parse_xml(file_path):
    """Reads an XML file and converts it into a list of dictionaries.
       This is a simple implementation that assumes each child of the root is a record."""
    findings = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for child in root:
            record = {}
            for element in child:
                record[element.tag] = element.text
            findings.append(record)
    except Exception as e:
        findings.append({"error": f"XML parsing error: {e}"})
    return findings

def standardize_findings(raw_data):
    """
    Converts raw parsed data into a standardized list of findings.
    Expected keys in each finding: 'file', 'line', 'message', 'risk'.
    For data files, you might only have limited information, so fill defaults.
    """
    standardized = []
    for entry in raw_data:
        if "error" in entry:
            standardized.append({
                "file": "Data File",
                "line": "N/A",
                "message": entry["error"],
                "risk": "Unknown"
            })
        else:
            standardized.append({
                "file": entry.get("file", "Data File"),
                "line": entry.get("line", "N/A"),
                "message": entry.get("message", "No message"),
                "risk": entry.get("risk", "Unknown")
            })
    return standardized

def scan_data_file(data_file):
    """
    Determines the type of the data file (CSV, JSON, or XML) based on the extension,
    parses it, and standardizes the output to match the findings structure.
    """
    if data_file.endswith(".csv"):
        raw = parse_csv(data_file)
    elif data_file.endswith(".json"):
        raw = parse_json(data_file)
    elif data_file.endswith(".xml"):
        raw = parse_xml(data_file)
    else:
        return [{"file": "Data File", "line": "N/A", "message": "Unsupported data file format", "risk": "Unknown"}]
    
    return standardize_findings(raw)
