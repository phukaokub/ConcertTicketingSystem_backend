from flask import Flask, session, redirect, url_for, request
from authlib.integrations.flask_client import OAuth
import requests
import boto3
import os
from dotenv import load_dotenv
import hmac
import hashlib
import base64

def generate_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(
        client_secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

app = Flask(__name__)
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')

# Configure OAuth for Amazon Cognito
oauth = OAuth(app)
oauth.register(
    name='oidc',
    authority='arn:aws:cognito-idp:us-east-1:814477798274:userpool/us-east-1_LfeJWW1e9',
    client_id='4slh5qi49igo9bmkn8p0kr8e91',
    client_secret='jl3pqjl06t2i580ddsp4fntvm7hv15kjggokbi1tnnam5gd01gq',
    server_metadata_url='https://cognito-idp.us-east-1.amazonaws.com/us-east-1_LfeJWW1e9/.well-known/jwks.json',
    client_kwargs={'scope': 'openid email phone'}
)

# Routes
@app.route('/')
def index():
    user = session.get('user')
    if user:
        return f'Hello, {user["email"]}. <a href="/logout">Logout</a>'
    else:
        return 'Welcome! Please <a href="/login">Login</a>.'
    
@app.route('/signup', methods=['POST'])
def signup():
    username = request.args.get('username')
    password = request.args.get('password')
    email = request.args.get('email')

    if not username or not password or not email:
        return {"error": "Missing required fields"}, 400

    try:
        # Initialize the Cognito Identity Provider client
        client = boto3.client('cognito-idp', region_name='us-east-1')

        # Generate the SECRET_HASH
        client_id = os.getenv('CLIENT_ID')
        client_secret = os.getenv('CLIENT_SECRET')
        secret_hash = generate_secret_hash(username, client_id, client_secret)

        # Call Cognito to sign up the user
        response = client.sign_up(
            ClientId=client_id,
            SecretHash=secret_hash,
            Username=username,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email}
            ]
        )
        return {"message": "User registered successfully"}, 200
    except client.exceptions.UsernameExistsException:
        return {"error": "Username already exists"}, 400
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/login', methods=['POST'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    if not username or not password:
        return {"error": "Missing username or password"}, 400

    try:
        client = boto3.client('cognito-idp', region_name='us-east-1')

        # Generate SECRET_HASH
        client_id = os.getenv('CLIENT_ID')
        client_secret = os.getenv('CLIENT_SECRET')
        secret_hash = generate_secret_hash(username, client_id, client_secret)

        # Initiate auth
        response = client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )
        return {"message": "Login successful", "tokens": response['AuthenticationResult']}, 200
    except client.exceptions.NotAuthorizedException:
        return {"error": "Incorrect username or password"}, 400
    except client.exceptions.UserNotFoundException:
        return {"error": "User not found"}, 404
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/authorize')
def authorize():
    token = oauth.oidc.authorize_access_token()
    user = token.get('userinfo')
    session['user'] = user
    print("Session after login:", session)
    return redirect(url_for('index'))

@app.route('/verify', methods=['POST'])
def verify():
    username = request.args.get('username')
    code = request.args.get('code')

    if not username or not code:
        return {"error": "Missing required fields"}, 400

    try:
        client = boto3.client('cognito-idp', region_name='us-east-1')

        # Generate SECRET_HASH
        client_id = os.getenv('CLIENT_ID')
        client_secret = os.getenv('CLIENT_SECRET')
        secret_hash = generate_secret_hash(username, client_id, client_secret)

        # Confirm the user's signup
        response = client.confirm_sign_up(
            ClientId=client_id,
            SecretHash=secret_hash,
            Username=username,
            ConfirmationCode=code
        )
        return {"message": "User verified successfully"}, 200
    except client.exceptions.CodeMismatchException:
        return {"error": "Invalid confirmation code"}, 400
    except Exception as e:
        return {"error": str(e)}, 500
    
@app.route('/getcurrentuser', methods=['GET'])
def get_current_user():
    user = session.get('user')
    if user:
        return {"user": user}, 200
    else:
        return {"error": "No user is logged in"}, 401

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6000)