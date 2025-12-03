import base64, time
import pyotp

# Read the decrypted seed
hex_seed = open("decrypted_seed.txt","r").read().strip()

print("hex_seed_len:", len(hex_seed))

# Convert hex → bytes → base32
seed_bytes = bytes.fromhex(hex_seed)
b32 = base64.b32encode(seed_bytes).decode('utf-8')

# Generate TOTP code (RFC 6238)
totp = pyotp.TOTP(b32, digits=6, interval=30, digest='sha1')

code = totp.now()
remaining = 30 - (int(time.time()) % 30)

print("TOTP code:", code)
print("valid_for:", remaining)
