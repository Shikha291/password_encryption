import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
password_from_user = input("Please enter your Password: ")
password = password_from_user.encode()

mysalt = b'\x10\x85&\xb8\xe3\x02\xb2XS-\x08\xc5Z\xca\x94\x18'
kdf = PBKDF2HMAC (
    algorithm = hashes.SHA256,
    length = 32,
    salt = mysalt,
    iterations = 100000,
    backend = default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(password))
print(key.decode())
