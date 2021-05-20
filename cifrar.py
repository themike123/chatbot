#####import for cript 
#https://pycryptodome.readthedocs.io/en/latest/src/features.html
from cryptography.fernet import Fernet
from requests.api import patch

from twofish import Twofish
import bcrypt
import base64, hashlib
    
import blowfish

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


import json
from base64 import b64encode, encode
from base64 import b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from dotenv import load_dotenv
load_dotenv() 

#Nuevo desarrollo
#Datos a encriptar senderId, Telefono, Id usuario, canal
#Cifrado Simetrico por bloques: DES(obsoleto), 3DES, AES


#RSA en python

#simetrico Blowfish, muy veloz, pero requiere mucho recurso al cambiar la clave 
#simetrico Twofish(por longitud de trama queda descartado), igual de rapido que Blowfish, es popular para dispositivos de bajos recursos, como las tarjetas SIM, y usa claves de cifrado de 
# hasta 256 bits.

print("============IIIIIIINNNNNNIIIIIIIICCCCIIIIIOOOO============")

trama = b"{senderid: 454564564654564, telefono: 5295126683331, IdCanal: 1 }"

key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt( trama )

print("=========================================")
print(f'Cifrado Fernet: {token}')
word = f.decrypt( token )
print( word.decode('utf-8') )
print("=========================================")


print('Informacion en base64 version 2:'+ b64encode(token).decode('utf-8'))

#byte_string = word.encode('utf-8')
encoded_data = base64.b64encode(token)
print(f'Informacion en base64: {encoded_data}')

decoded_data = base64.b64decode(encoded_data)
print(f'Informacion en fernet: {decoded_data}')

encoded_data32 = base64.b32encode(token)
print(f'Informacion en base32: {encoded_data}')


#Requirements : sudo apt-get install build-essential libffi-dev python-dev
print("=========================================")
password = trama
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print( f'Bcrypt hash:{hashed}' )

if bcrypt.checkpw(password, hashed):
    print("It Matches!")
else:
    print("It Does not Match :(")


print("=========================================")


cipher_little = blowfish.Cipher(b"my key", byte_order = "little")

print(cipher_little)

string_to_hash = '123'
hash_object = hashlib.sha256(str(string_to_hash).encode('utf-8'))
print('Hash', hash_object.hexdigest())


print("=========================================")

""" key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(trama) + encryptor.finalize()
print(ct)
decryptor = cipher.decryptor()
decryptor.update(ct) + decryptor.finalize() """


print("=========================================")

key = bcrypt.kdf(
password=trama,
salt=b'salt',
desired_key_bytes=32,
rounds=100)

print(key)

print("=========================================")
#pip3 install pycryptodome
#pip3 install pycryptodomex
#pip3 install pycrypto



print("=============================================")
print("=============================================")


plaintext = trama

key_critpy = os.environ.get("KEY_CHACHA20").encode('utf-8')

cipher = ChaCha20.new(key=key_critpy)
ciphertext = cipher.encrypt(plaintext) #return bytes

nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ciphertext).decode('utf-8')


result = json.dumps({'nonce':nonce, 'ciphertext':ct})



b64 = json.loads(result)

nonce2 = b64decode(b64['nonce'])
ciphertext2 = b64decode(b64['ciphertext'])


cipher = ChaCha20.new(key=key_critpy, nonce=nonce2)
plaintext = cipher.decrypt(ciphertext2)

print( plaintext )


print("=============================================")
print("=============================================")


plaintext = trama
secret = os.environ.get("KEY_CHACHA20").encode('utf-8')
cipher = ChaCha20.new(key=secret)
msg = cipher.nonce + cipher.encrypt(plaintext)

print( b64encode(msg).decode('utf-8')  )
print( b64encode(msg) )

print(msg)

msg_nonce = msg[:8]
ciphertext = msg[8:]


cipher2 = ChaCha20.new(key=secret, nonce=msg_nonce)
plaintext = cipher2.decrypt(ciphertext)

print(plaintext)

print("=============================================")

#CCM, GCM, EAX o ChaCha20Poly1305.
#
#


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

hdr = b'To your eyes only'
plaintext = trama
key = b'p2s5v8y/B?E(H+Mb'
nonce = get_random_bytes(11)
cipher = AES.new(key, AES.MODE_CCM, nonce)
cipher.update(hdr)

msg = nonce, hdr, cipher.encrypt(plaintext), cipher.digest()

print( f"Esto es el cifrado: {b64encode(msg[2]).decode('utf-8')}")

# We assume that the tuple ``msg`` is transmitted to the receiver:

nonce, hdr, ciphertext, mac = msg
key = b'p2s5v8y/B?E(H+Mb'
cipher = AES.new(key, AES.MODE_CCM, nonce)
cipher.update(hdr)
plaintext = cipher.decrypt(ciphertext)
try:
    cipher.verify(mac)
    print(f"The message is authentic: hdr={hdr}, pt={plaintext}")
except ValueError:
    print("Key incorrect or message corrupted")

print("=============================================")
#pip install python-gcm
