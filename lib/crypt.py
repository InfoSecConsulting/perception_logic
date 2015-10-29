from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import urandom, getenv
from binascii import hexlify


def encrypt_string(string):
  password = str.encode(getenv('BOBHADABABY'))
  salt = hexlify(urandom(16))
  kdf = PBKDF2HMAC(algorithm=hashes.SHA1,
                   length=32,
                   salt=salt,
                   iterations=100000,
                   backend=default_backend())
  key = urlsafe_b64encode(kdf.derive(password))
  f = Fernet(key)
  encrypted_string = f.encrypt(string)
  return encrypted_string, salt

def decrypt_string(encrypted_string, salt):
  password = str.encode(getenv('BOBHADABABY'))
  kdf = PBKDF2HMAC(algorithm=hashes.SHA1,
                   length=32,
                   salt=salt,
                   iterations=100000,
                   backend=default_backend())
  key = urlsafe_b64encode(kdf.derive(password))
  f = Fernet(key)
  string = f.decrypt(encrypted_string)
  return string
