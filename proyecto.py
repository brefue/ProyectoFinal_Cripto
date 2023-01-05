import time
#ChaCha20
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
inicioChaCha = time.time()
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
print(ct)
decryptor = cipher.decryptor()
decryptor.update(ct) + decryptor.finalize()
finChaCha = time.time()
print(finChaCha-inicioChaCha)

print()
#AES-EBC
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
# the buffer needs to be at least len(data) + n - 1 where n is cipher/mode block size in bytes
buf = bytearray(31)
len_encrypted = encryptor.update_into(b"a secret message", buf)
# get the ciphertext from the buffer reading only the bytes written to it (len_encrypted)
ct = bytes(buf[:len_encrypted]) + encryptor.finalize()
print(ct)
decryptor = cipher.decryptor()
len_decrypted = decryptor.update_into(ct, buf)
# get the plaintext from the buffer reading only the bytes written (len_decrypted)
bytes(buf[:len_decrypted]) + decryptor.finalize()

print()
#AES-CBC
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
print(ct)
decryptor = cipher.decryptor()
decryptor.update(ct) + decryptor.finalize()

print()

#SHA2
import hashlib
plain = "a secret message"
print(hashlib.sha384(plain.encode()).hexdigest())
print()
print(hashlib.sha512(plain.encode()).hexdigest())
print()

#SHA3
print(hashlib.sha3_384(plain.encode()).hexdigest())
print()
print(hashlib.sha3_512(plain.encode()).hexdigest())
print()


#RSA-OAEP
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

message = b"encrypted data"
public_key = private_key.public_key()
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(plaintext)

print()
#RSA-PSS
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()


message = b"A message I want to sign"
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print(signature)


#ECDSA - Prime Field
from ecdsa import SigningKey
sk = SigningKey.generate() # uses NIST192p
vk = sk.verifying_key
signature = sk.sign(b"message")
print(signature)

#ECDSA - Binary Field
