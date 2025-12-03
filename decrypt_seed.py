import base64
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load RSA private key
def load_private_key(path="student_private.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def main():
    # Step 1: Read encrypted seed (base64 text)
    try:
        b64 = open("encrypted_seed.txt", "rb").read().strip()
    except Exception as e:
        print("ERROR reading encrypted_seed.txt:", e, file=sys.stderr)
        sys.exit(1)

    if not b64:
        print("ERROR: encrypted_seed.txt is empty", file=sys.stderr)
        sys.exit(2)

    # Step 2: Base64 decode the encrypted seed
    try:
        ciphertext = base64.b64decode(b64)
    except Exception as e:
        print("Base64 decode failed:", e, file=sys.stderr)
        sys.exit(3)

    # Step 3: Load private key
    try:
        priv = load_private_key("student_private.pem")
    except Exception as e:
        print("Failed to load private key:", e, file=sys.stderr)
        sys.exit(4)

    # Step 4: RSA OAEP SHA-256 decrypt
    try:
        plaintext = priv.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print("Decryption failed:", e, file=sys.stderr)
        sys.exit(5)

    # Step 5: Convert bytes → lowercase hex string
    seed = plaintext.decode("utf-8").strip().lower()

    # Validate
    if len(seed) != 64 or any(c not in "0123456789abcdef" for c in seed):
        print("Decrypted seed invalid:", seed, file=sys.stderr)
        sys.exit(6)

    # Output
    print(seed)

    with open("decrypted_seed.txt", "w") as f:
        f.write(seed)

if __name__ == "__main__":
    main()
