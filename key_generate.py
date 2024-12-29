import secrets

# Generate a 24-byte random key and encode it in base64
secret_key = secrets.token_hex(24)  # 24 bytes gives a 48-character hex key

print("Generated Secret Key:", secret_key)
