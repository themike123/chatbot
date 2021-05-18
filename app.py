from flask import Flask, request
import flask
from flask.helpers import flash
import requests
import os

#####import for cript 
from cryptography.fernet import Fernet

from twofish import Twofish
import bcrypt
import base64, hashlib
from base64 import b64encode
import blowfish


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#####


from dotenv import load_dotenv
load_dotenv() 

app = Flask (__name__)

@app.route('/')
def index():
    print( os.environ.get("VERIFY_TOKEN_FACEBOOK") )
    return 'CHATBOT'

def get_bot_response(message):    
    return "Esta es la respuesta de: '{}'".format(message)


def verify_webhook(request):
    #get attr request
    mode = request.args.get("hub.mode")
    verify_token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode and verify_token:
        if mode == 'subscribe' and verify_token == os.environ.get("VERIFY_TOKEN_FACEBOOK"):            
            return flask.Response(challenge, 200)
        else:        
            return flask.Response("Token incorrecto", 403)
        


def respond(sender, message):    
    response = get_bot_response(message)
    send_message(sender, response)


def send_message(recipient_id, text):
    """Send a response to Facebook"""
    payload = {
        'message': {
            'text': text
        },
        'recipient': {
            'id': recipient_id
        },
        'notification_type': 'regular'
    }

    auth = {
        'access_token': os.environ.get("ACCESS_TOKEN_FACEBOOK")
    }

    response = requests.post(
        os.environ.get("API_GRAPH"),
        params=auth,
        json=payload
    )

    return response.json()


def is_user_message(message):
    """Check if the message is a message from the user"""
    return (message.get('message') and
            message['message'].get('text') and
            not message['message'].get("is_echo"))

#Webhook
@app.route('/webhook',  methods=['GET', 'POST'])
def listen():
    if request.method == 'GET':
        #return response verify_webhook
        return verify_webhook(request)
    elif request.method == 'POST':                    
        #get data
        data = request.json

        if data['object'] == 'page':#Checks if this is an event from a page subscription
            
            for x in data['entry'][0]['messaging']:

                # if x['message']:
                #     handleMessage(x['sender']['id'], x['message'])
                # elif x['postback']:
                #     handlePostback(x['sender']['id'], x['postback'])


                if is_user_message(x):
                    text = x['message']['text']
                    sender_id = x['sender']['id']
                    respond(sender_id, text)

            return flask.Response('EVENT_RECEIVED',200)

        else:
            return flask.Response(404)

        
    #return flask.Response("Chatbot Grupo Salinas", 200)

def handlePostback(psdi,postback):
    return "postback"

def handleMessage(psdi, message):

    #Checks if the message contains text
    if message.text:                
        response = f'Esta es la respuesta de: {message.text}'
    elif message.attachments:
        
        attachmentUrl = message.attachments[0].payload.url;

        response = {
            'attachment': {
                'type': 'template',
                'payload': {
                    'template_type': 'generic',
                    'elements': [{
                        'title': 'Is this the right picture?',
                        'subtitle': 'Tap a button to answer.',
                        'image_url': attachmentUrl,
                        'buttons': [{
                            'type': 'postback',
                            'title': 'Yes!',
                            'payload': 'yes',
                        },{
                            'type': 'postback',
                            'title': 'No!',
                            'payload': 'no',
                        }]
                    }]
                }
            }
        }

        callSendAPI(psdi, response)


def callSendAPI(senderPsid, response):
    payload = {
        'message': {
            'text': response
        },
        'recipient': {
            'id': senderPsid
        },
        'notification_type': 'regular'
    }

    auth = {
        'access_token': os.environ.get("ACCESS_TOKEN_FACEBOOK")
    }

    response = requests.post(
        os.environ.get("API_GRAPH"),
        params=auth,
        json=payload
    )

    return response.json()

#Nuevo desarrollo
#Datos a encriptar senderId, Telefono, Id usuario, canal
#Cifrado Simetrico por bloques: DES(obsoleto), 3DES, AES


#RSA en python

#simetrico Blowfish, muy veloz, pero requiere mucho recurso al cambiar la clave 
#simetrico Twofish(por longitud de trama queda descartado), igual de rapido que Blowfish, es popular para dispositivos de bajos recursos, como las tarjetas SIM, y usa claves de cifrado de 
# hasta 256 bits.

print("============IIIIIIINNNNNNIIIIIIIICCCCIIIIIOOOO============")

trama = b"{senderId: 454564564654564, telefono: 5295126683331, user_id: 12334323432 , canal: whatsapp }"

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


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX)

#nonce = cipher.nonce
#ciphertext, tag = cipher.encrypt_and_digest(data)

print("=========================================")

import json
from base64 import b64encode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = trama
key = get_random_bytes(32)
cipher = ChaCha20.new(key=key)
ciphertext = cipher.encrypt(plaintext)

print(ciphertext)

nonce = b64encode(cipher.nonce).decode('utf-8')

ct = b64encode(ciphertext).decode('utf-8')

result = json.dumps({'nonce':nonce, 'ciphertext':ct})
print(result)

#Only development(run in terminal: python3 app.py), remove in production
if __name__ == "__main__":
    app.run(debug=True)