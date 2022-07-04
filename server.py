from urllib.parse import urlencode, urlunsplit
from flask import Flask, jsonify, redirect, render_template, request, session
from configparser import ConfigParser
import requests, json, jwt, time

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

    existingToken = False

    if session.get("id_token") != None and session.get("access_token") != None :
        existingToken = True
        print("Existing Tokens exist")  

    return render_template('index.html', clientid = CLIENT_ID, scope = SCOPE, existingToken = existingToken)

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
        print(r.text)
        return redirect('/')

    payload = json.loads(r.text)

    access_token = payload['access_token']
    id_token = payload['id_token']

    session['access_token'] = access_token
    session['id_token'] = id_token

    return redirect('/displayTokens')

@svr.route("/displayTokens")
def displayTokens() :

    access_token = session['access_token']
    id_token = session['id_token']

    try :
        id_token_claims = jwt.decode(id_token, options={"verify_signature": False})
        id_token_expiry_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(id_token_claims['exp']))
    except Exception as e:
        id_token_expiry_time = "ERROR DECODING JWT"
        print("Failed to decode JWT" + str(e))
    
    try :
        access_token_claims = jwt.decode(access_token, options={"verify_signature": False})
        access_token_expiry_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(access_token_claims['exp']))
    except Exception as e:
        access_token_expiry_time  = "ERROR DECODING JWT"
        print("Failed to decode JWT" + str(e))

    return render_template('displayTokens.html', access_token = access_token, access_token_expiry = access_token_expiry_time, id_token = id_token, id_token_expiry = id_token_expiry_time)

@svr.route("/login")
def login() :

    redirectParams = {
        'client_id': CLIENT_ID,
        'scope': SCOPE,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI
    }

    redirectUrl = urlunsplit(('https', IDP_DOMAIN, AUTHORIZE_PATH, urlencode(redirectParams), ""))
    return redirect(redirectUrl)


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