from flask import Flask, request
import flask
from flask.helpers import flash
import requests
import os

#####import for cript 
from cryptography.fernet import Fernet
from twofish import Twofish
import bcrypt
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



@app.route('/getip',  methods=['GET', 'POST'])
def getIP():
    hostname = socket.gethostname()    
    IPAddr = socket.gethostbyname(hostname) 
    print(request)
    return request.remote_addr+" , "+flask.request.remote_addr+", "+ request.environ.get('HTTP_X_REAL_IP', request.remote_addr)+" , "+ hostname +" , "+IPAddr


#Nuevo desarrollo
#Datos a encriptar senderId, Telefono, Id usuario, canal
#Cifrado Simetrico por bloques: DES(obsoleto), 3DES, AES


#RSA en python

#simetrico Blowfish, muy veloz, pero requiere mucho recurso al cambiar la clave 
#simetrico Twofish, igual de rapido que Blowfish, es popular para dispositivos de bajos recursos, como las tarjetas SIM, y usa claves de cifrado de 
# hasta 256 bits.


key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"Miguel Ramirez Cruz")

print(token)
print(token.decode('utf-8'))
word = f.decrypt( token )
print( word.decode('utf-8') )


T = Twofish(b'*secret*')
x = T.encrypt(b'YELLOWSUBMARINES')
print(x)
print(T.decrypt(x).decode())


print("/n/n")

password = b"super secret password"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

print(hashed)

if bcrypt.checkpw(password, hashed):
    print("It Matches!")
else:
    print("It Does not Match :(")



print("/n/n")

key = bcrypt.kdf(
password=b'password',
salt=b'salt',
desired_key_bytes=32,
rounds=100)

print(key)

#Only development(run in terminal: python3 app.py), remove in production
if __name__ == "__main__":
    app.run(debug=True)