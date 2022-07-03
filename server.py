from urllib.parse import urlencode, urlunsplit
from flask import Flask, jsonify, redirect, render_template, request, session
from configparser import ConfigParser
import requests, json

svr = Flask(__name__)
config_object = ConfigParser()
config_object.read("config/auth0_personal.ini")

svr.secret_key = 'BAD_SECRET_KEY'

CLIENT_ID       = config_object["IDP"]["CLIENT_ID"]
CLIENT_SECRET   = config_object["IDP"]["CLIENT_SECRET"]
SCOPE           = config_object["IDP"]["SCOPE"]
REDIRECT_URI    = config_object["IDP"]["REDIRECT_URI"]
IDP_DOMAIN      = config_object["IDP"]["IDP_DOMAIN"]
AUTHORIZE_PATH  = config_object["IDP"]["AUTHORIZE_PATH"]
LOGOUT_PATH     = config_object["IDP"]["LOGOUT_PATH"]
TOKEN_PATH      = config_object["IDP"]["TOKEN_PATH"]
USERINFO_PATH   = config_object["IDP"]["USERINFO_PATH"]

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
    session['id_token'] = id_token

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


@svr.route("/logout")
def logout() :
    mydict = {
        'client_id': CLIENT_ID,
        'returnTo': "http://localhost/"
    }
    session.clear()

    return redirect(urlunsplit(('https', IDP_DOMAIN, LOGOUT_PATH, urlencode(mydict), "")))


@svr.route("/userinfo")
def userinfo() :
    return makeSecuredAPICall(IDP_DOMAIN, USERINFO_PATH, '')
 
@svr.route("/externalendpoint")
def callExternalEndpount() :
    
    data = {'CLIENT_ID'          : '1234',  
            'CLIENT_SECRET'     : 'Secret'}

    r = makeSecuredAPICall('http://localhost', 'testexternal', data)


def makeSecuredAPICall(domain, path, params) :
    
    accessToken = session['access_token']

    if (accessToken == '') :
        print('ERROR: No access token in session')
        return redirect('/')

    header = {'Authorization' : 'Bearer {}'.format(accessToken)}

    url = urlunsplit(('https', domain, path, urlencode(params), ''))

    print('Making secured API call to: ' + url + ' with access token: ' + accessToken)

    r = requests.get(url, headers= header)

    if(r.status_code != 200) :
        return r.text

    return r.json()

svr.run(debug=True, host="0.0.0.0", port=80)