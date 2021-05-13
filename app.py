from flask import Flask, request
import flask
from flask.helpers import flash
import requests
import os

from dotenv import load_dotenv
load_dotenv() 

app = Flask (__name__)

@app.route('/')
def hello_word():
    print( os.environ.get("VERIFY_TOKEN_FACEBOOK") )
    return 'CHATBOT'

def get_bot_response(message):
    """This is just a dummy function, returning a variation of what
    the user said. Replace this function with one connected to chatbot."""
    return "This is a dummy response to '{}'".format(message)



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
    """Formulate a response to the user and
    pass it on to a function that sends it."""
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
        payload = request.json
        event = payload['entry'][0]['messaging']
        for x in event:
            if is_user_message(x):
                text = x['message']['text']
                sender_id = x['sender']['id']
                respond(sender_id, text)

        return "ok"
        
    #return flask.Response("Chatbot Grupo Salinas", 200)



#Only development(run in terminal: python3 app.py), remove in production
if __name__ == "__main__":
    app.run(debug=True)