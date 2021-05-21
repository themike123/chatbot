import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

header = b"header"
data = b"{senderid: 454564564654564, telefono: 5295126683331, IdCanal: 1 }"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_OCB)
cipher.update(header)
ciphertext, tag = cipher.encrypt_and_digest(data)

json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag]  ]
result = json.dumps(dict(zip(json_k, json_v)))
print(result)
#{"nonce": "I7E6PKxHNYo2i9sz8W98", "header": "aGVhZGVy", "ciphertext": "nYJnJ8jC", "tag": "0UbFcmO9lqGknCIDWRLALA=="}


# We assume that the key was securely shared beforehand
try:
    b64 = json.loads(result)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    jv = {k:b64decode(b64[k]) for k in json_k}

    cipher = AES.new(key, AES.MODE_OCB, nonce=jv['nonce'])
    cipher.update(jv['header'])
    plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    print(plaintext)
except ValueError:
    print("Incorrect decryption")