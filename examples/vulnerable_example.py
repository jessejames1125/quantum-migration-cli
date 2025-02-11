import hashlib
import rsa

def insecure_hash(data):
    # MD5 is insecure.
    return hashlib.md5(data.encode()).hexdigest()

def insecure_encrypt(data):
    # Simulate insecure RSA by using a very small modulus.
    public_key = rsa.PublicKey(65537, 61)  # 61 (2 digits) triggers our RSA rule.
    return rsa.encrypt(data.encode(), public_key)

if __name__ == "__main__":
    data = "sensitive data"
    print("MD5:", insecure_hash(data))
    print("Encrypted:", insecure_encrypt(data))
