from urllib.parse import urlencode, urlunsplit
from flask import Flask, redirect, render_template, request
import requests
import json

svr = Flask(__name__)

CLIENT_ID = 'W5z7HlQslHkoQcVsKxokM1jYaijvtRfh'
CLIENT_SECRET = 'QeEMuF-9lYMlcKDOuKkrKGWU_gzRPYcpkoI8B0IHJKNHUHfrZ6yFTp2BN-whiPWo'
SCOPE = 'openid'
REDIRECT_URI = 'http://localhost/callback'
IDP_DOMAIN = 'dev-siesgeoh.us.auth0.com'

@svr.route("/")
def index() :
    return render_template('index.html', clientid = CLIENT_ID, scope = SCOPE)

@svr.route("/callback")
def callback() :
    args = request.args
    code = args.get("code")

    data = {'code': code,  
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'redirect_uri': REDIRECT_URI,
            'grant_type': 'authorization_code'}


    r = requests.post(urlunsplit(('https', IDP_DOMAIN, 'oauth/token', '', '')), data = data)

    payload = json.loads(r.text)

    print(r.text)

    access_token = payload['access_token']
    id_token = payload['id_token']

    return render_template('callback.html', code = code, access_token = access_token, id_token = id_token)

@svr.route("/login")
def login() :
    mydict = {
        'client_id': CLIENT_ID,
        'scope': SCOPE,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI
    }
    return redirect(urlunsplit(('https', IDP_DOMAIN, 'authorize', urlencode(mydict), "")))

svr.run(debug=True, host="0.0.0.0", port=80)