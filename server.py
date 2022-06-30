from urllib.parse import urlencode, urlunsplit
from flask import Flask, redirect, render_template, request, session
import requests, json

svr = Flask(__name__)

svr.secret_key = 'BAD_SECRET_KEY'

CLIENT_ID       = 'W5z7HlQslHkoQcVsKxokM1jYaijvtRfh'
CLIENT_SECRET   = 'QeEMuF-9lYMlcKDOuKkrKGWU_gzRPYcpkoI8B0IHJKNHUHfrZ6yFTp2BN-whiPWo'
SCOPE           = 'openid email profile'
REDIRECT_URI    = 'http://localhost/callback'
IDP_DOMAIN      = 'dev-siesgeoh.us.auth0.com'
AUTHORIZE_PATH  = 'authorize'
TOKEN_PATH      = 'oauth/token'

@svr.route("/")
def index() :
    return render_template('index.html', clientid = CLIENT_ID, scope = SCOPE)

@svr.route("/callback")
def callback() :
    code = request.args.get("code")

    session['code'] = code

    return render_template('callback.html', code = code)

@svr.route("/exchange")
def exchange() :

    code = session['code']

    data = {'code'      : code,  
        'client_id'     : CLIENT_ID,
        'client_secret' : CLIENT_SECRET,
        'redirect_uri'  : REDIRECT_URI,
        'grant_type'    : 'authorization_code'}

    r = requests.post(urlunsplit(('https', IDP_DOMAIN, TOKEN_PATH, '', '')), data = data)

    if(r.status_code != 200) :
        return redirect('/')

    payload = json.loads(r.text)

    print(payload)

    access_token = payload['access_token']
    id_token = payload['id_token']

    session['access_token'] = access_token

    return render_template('exchange.html', access_token = access_token, id_token = id_token)


@svr.route("/login")
def login() :
    mydict = {
        'client_id': CLIENT_ID,
        'scope': SCOPE,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI
    }
    return redirect(urlunsplit(('https', IDP_DOMAIN, AUTHORIZE_PATH, urlencode(mydict), "")))


@svr.route("/userinfo")
def userinfo() :

    accessToken = session['access_token']

    if (accessToken == '') :
        print('ERROR: No access token in session')
        return redirect('/')

    header = {'Authorization' : 'Bearer {}'.format(accessToken)}

    r = requests.get(urlunsplit(('https', IDP_DOMAIN, 'userinfo', '', '')), headers= header)

    if(r.status_code != 200) :
        return redirect('/')

    payload = json.loads(r.text)

    print(payload)

    sub = payload['sub']
    email = payload['email']
    nickname = payload['nickname']
    picture = payload['picture']

    return render_template('userinfo.html', sub = sub, email = email, nickname = nickname, picture = picture)

 
svr.run(debug=True, host="0.0.0.0", port=80)