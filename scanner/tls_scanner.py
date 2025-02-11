import ssl
from OpenSSL import crypto

def scan_tls_certificate(host, port=443):
    print(f"Scanning TLS certificate on {host}:{port} ...")
    try:
        cert = ssl.get_server_certificate((host, port))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        algo = x509.get_signature_algorithm().decode() if isinstance(x509.get_signature_algorithm(), bytes) else x509.get_signature_algorithm()
        key = x509.get_pubkey()
        key_bits = key.bits()
        risk = "Low"
        if "rsa" in algo.lower() and key_bits < 3072:
            risk = "High"
        message = f"{algo} with {key_bits} bits"
        return [{
            "file": "TLS",
            "line": "N/A",
            "message": message,
            "risk": risk
        }]
    except Exception as e:
        return [{
            "file": "TLS",
            "line": "N/A",
            "message": f"Error scanning TLS certificate: {e}",
            "risk": "Unknown"
        }]
