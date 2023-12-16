from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding
import os

root_key = b'00112233445566778899aabbccddeeff'

def generate_dh_key_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def ratchet_dh(prik, pubk):
    shared_key = prik.exchange(pubk)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def ratchet_symmetric(shared_key, root_key):
    h = HMAC(shared_key, hashes.SHA256(), backend=default_backend())
    h.update(root_key)
    return h.finalize() # New key

def encrypt(key, plaintext):
    # Generate a random 128-bit IV.
    iv = os.urandom(16)
    
    # Construct an AES-128-CBC Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    
    # Encrypt the plaintext and get the associated ciphertext.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return (iv, ciphertext)

def decrypt(key, iv, ciphertext):
    # Construct a Cipher object, with the key, iv
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()
    
    # Decryption gets us the plaintext.
    return decryptor.update(ciphertext) + decryptor.finalize()



