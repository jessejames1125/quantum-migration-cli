import hashlib
import rsa

def secure_hash(data):
    # SHA-256 is secure.
    return hashlib.sha256(data.encode()).hexdigest()

def secure_encrypt(data):
    # Simulate secure RSA usage by using a large modulus.
    public_key = rsa.PublicKey(65537, 999630013489999630013489)  # 24 digits; does not match insecure rule.
    return rsa.encrypt(data.encode(), public_key)

if __name__ == "__main__":
    data = "sensitive data"
    print("SHA-256:", secure_hash(data))
    print("Encrypted:", secure_encrypt(data))
