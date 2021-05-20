from flask import Flask, request
import flask
from flask.helpers import flash
import requests
import os

#####import for cript 
#https://pycryptodome.readthedocs.io/en/latest/src/features.html
from cryptography.fernet import Fernet
from requests.api import patch

import base64, hashlib

import json
from base64 import b64encode, b64decode

from requests.models import requote_uri
#from base64 import #Haber si se quita esto, sino da errores se va
from Crypto.Cipher import ChaCha20
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

print("============IIIIIIINNNNNNIIIIIIIICCCCIIIIIOOOO============")

trama = b"{senderid: 454564564654564, telefono: 5295126683331, IdCanal: 1 }"

key = os.environ.get("KEY_FERNET").encode('utf-8') # Fernet.generate_key()

f = Fernet(key)
token = f.encrypt( trama )

print("=========================================")
print(f'Cifrado Fernet: {token}')
word = f.decrypt( token )
print( word.decode('utf-8') )
print("=========================================")


#pip3 install pycryptodome
#pip3 install pycryptodomex
#pip3 install pycrypto

@app.route('/cifrar',  methods=['GET'])
def cifrar():        
    
    senderid = request.args.get('senderid')
    telefono = request.args.get('telefono')
    idcanal = request.args.get('IdCanal')

    return 
    
    plaintext = request.args.get('trama').encode('utf-8')

    key_critpy = os.environ.get("KEY_CHACHA20").encode('utf-8')
    
    cipher = ChaCha20.new(key=key_critpy)
    ciphertext = cipher.encrypt(plaintext)    

    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')

    return(result)


    plaintext = trama

    key_critpy = os.environ.get("KEY_CHACHA20").encode('utf-8')

    cipher = ChaCha20.new(key=key_critpy)
    ciphertext = cipher.encrypt(plaintext) #return bytes

    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')

    return jsonify(nonce=nonce, ciphertext=ct)


@app.route('/descifar',  methods=['GET'])
def descifar():
    try:
        b64 = json.loads(json_input)
        nonce = b64decode(b64['nonce'])
        ciphertext = b64decode(b64['ciphertext'])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print("The message was " + plaintext)
    except ValueError :
        print("Incorrect decryption")


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



#Only development(run in terminal: python3 app.py), remove in production
if __name__ == "__main__":
    app.run(debug=True)