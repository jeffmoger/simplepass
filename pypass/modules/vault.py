import os
import base64
import pickle

from passlib.hash import pbkdf2_sha256 as p_hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def get_key(master, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(master))
    return key


def encrypt(master, salt, password):
    f = Fernet(get_key(master, salt))
    encrypted = f.encrypt(password)
    return encrypted


def decrypt(master, salt, password):
    f = Fernet(get_key(master, salt))
    decrypted = f.decrypt(password)
    return decrypted


def pickle_bytes(token):
    p = pickle.dumps(token)
    return base64.b64encode(p).decode('ascii')


def unpickle_string(token):
    p = base64.b64decode(token)
    return pickle.loads(p)


def lock(key, salt1, salt2, password):
    encrypted = pickle_bytes(encrypt(key, salt2, encrypt(key,salt1,password)))
    return encrypted

def unlock(key, salt1, salt2, token):
    decrypted = decrypt(key, salt1, decrypt(key, salt2, unpickle_string(token)))
    return decrypted.decode()


def example():
    master = ('masterpassword').encode()
    password = ('a_new_password').encode()
    salt1 = ('EC6873C47AD2F3FABCCC62AF564996F3F84ECD446433DDE').encode()
    salt2 = os.urandom(16)

    key = get_key(master,salt1)
    encrypted = lock(key, salt1, salt2, password)
    token = encrypted
    decrypted = unlock(key, salt1, salt2, token)
    print('    Password: %s' % password)
    print('    Salt: %s' % pickle_bytes(salt2))
    print('    Token: %s' % encrypted)
    print('    Decrypted: %s' % decrypted)
