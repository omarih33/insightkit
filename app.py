
from flask import Flask, redirect, request, session, url_for, render_template
import requests
import os
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secure key for session encryption

# Logging configuration for better diagnostics
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Read environment variables for CLIENT_ID and CLIENT_SECRET
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

if not CLIENT_ID or not CLIENT_SECRET:
    logger.error("CLIENT_ID and CLIENT_SECRET environment variables must be set.")
    raise RuntimeError("CLIENT_ID and CLIENT_SECRET environment variables must be set.")

REDIRECT_URI = "https://insightkit-95170003f5ee.herokuapp.com/oauth_callback"
AUTH_URL = "https://app.convertkit.com/oauth/authorize"
TOKEN_URL = "https://api.convertkit.com/oauth/token"
API_BASE_URL = "https://api.convertkit.com/v4"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authorize')
def authorize():
    logger.info("Starting authorization process")
    auth_url = f"{AUTH_URL}?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}"
    return redirect(auth_url)

@app.route('/oauth_callback')
def oauth_callback():
    code = request.args.get('code')
    if not code:
        logger.error("No authorization code returned")
        return "No authorization code returned", 400

    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI
    }
    token_response = requests.post(TOKEN_URL, data=token_data)
    
    if token_response.status_code != 200:
        logger.error(f"Failed to get token: {token_response.text}")
        return f"Failed to get token: {token_response.text}", token_response.status_code
    
    token_json = token_response.json()
    session['access_token'] = token_json['access_token']
    session['refresh_token'] = token_json['refresh_token']
    
    return redirect(url_for('broadcasts'))

@app.route('/broadcasts')
def broadcasts():
    if 'access_token' not in session:
        return redirect(url_for('index'))
    
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.get(f"{API_BASE_URL}/broadcasts", headers=headers)
    
    if response.status_code == 401:  # Token might be expired
        logger.info("Access token expired, refreshing token")
        refresh_token()
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        response = requests.get(f"{API_BASE_URL}/broadcasts", headers=headers)
    
    if response.status_code != 200:
        logger.error(f"Failed to fetch broadcasts: {response.text}")
        return f"Failed to fetch broadcasts: {response.text}", response.status_code

    broadcasts = response.json()
    return render_template('broadcasts.html', broadcasts=broadcasts)

def refresh_token():
    logger.info("Refreshing access token")
    refresh_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": session['refresh_token'],
        "grant_type": "refresh_token"
    }
    refresh_response = requests.post(TOKEN_URL, data=refresh_data)
    
    if refresh_response.status_code != 200:
        logger.error(f"Failed to refresh token: {refresh_response.text}")
        raise RuntimeError(f"Failed to refresh token: {refresh_response.text}")
    
    refresh_json = refresh_response.json()
    session['access_token'] = refresh_json['access_token']
    session['refresh_token'] = refresh_json['refresh_token']

if __name__ == '__main__':
    app.run(debug=True)
