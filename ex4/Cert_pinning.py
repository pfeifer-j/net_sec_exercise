import ssl
import urllib.request

# Define the URL and expected public key or hash
url = "https://example.com"
expected_public_key = (
    b"-----BEGIN PUBLIC KEY-----\n...Your public key here...\n-----END PUBLIC KEY-----"
)

# Create a custom SSL context
context = ssl.create_default_context()

# Pin the public key
context.check_hostname = True
context.verify_mode = ssl.CERT_PINNED
context.purpose = ssl.Purpose.SERVER_AUTH
context.pinned_public_key = expected_public_key

# Make the HTTPS request
try:
    with urllib.request.urlopen(url, context=context) as response:
        html = response.read()
        print(html)
except Exception as e:
    print("Error:", e)
