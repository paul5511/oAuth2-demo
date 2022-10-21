from urllib.parse import urlencode, urlunsplit
from flask import Flask, redirect, render_template, request, session, url_for
from configparser import ConfigParser
import requests, json, jwt, time, secrets, urllib.parse, pkce

svr = Flask(__name__)
config_object = ConfigParser()
config_object.read("config/tc_stage.ini")

svr.secret_key = secrets.token_urlsafe(16)

CLIENT_ID       = config_object["IDP"]["CLIENT_ID"]
CLIENT_SECRET   = config_object["IDP"]["CLIENT_SECRET"]
SCOPE           = config_object["IDP"]["SCOPE"]
REDIRECT_URI    = config_object["IDP"]["REDIRECT_URI"]
IDP_DOMAIN      = config_object["IDP"]["IDP_DOMAIN"]
AUTHORIZE_PATH  = config_object["IDP"]["AUTHORIZE_PATH"]
LOGOUT_PATH     = config_object["IDP"]["LOGOUT_PATH"]
TOKEN_PATH      = config_object["IDP"]["TOKEN_PATH"]
USERINFO_PATH   = config_object["IDP"]["USERINFO_PATH"]

API_DOMAIN          = config_object["API"]["DOMAIN"]
CONTACT_PATH        = config_object["API"]["CONTACT_PATH"]
CONTACT_CLIENT_ID   = config_object["API"]["CONTACT_CLIENT_ID"]
CONTACT_SECRET      = config_object["API"]["CONTACT_SECRET"]
CONSENT_PATH        = config_object["API"]["CONSENT_PATH"]
CONSENT_CLIENT_ID   = config_object["API"]["CONSENT_CLIENT_ID"]
CONSENT_SECRET      = config_object["API"]["CONSENT_SECRET"]

@svr.route("/")
def index() :
    existingIdentityTokenExists = False

    if session.get("id_token") != None :
        existingIdentityTokenExists = True
        
    loginRedirectUrl =  urllib.parse.unquote_plus(createAuthorizePath())

    return render_template('index.html', idpdomain = IDP_DOMAIN, clientid = CLIENT_ID, scope = SCOPE, state = svr.secret_key, existingToken = existingIdentityTokenExists, loginRedirectUrl = loginRedirectUrl)

@svr.route("/callback")
def callback() :

    code = request.args.get("code")
    state = request.args.get("state")

    session['code'] = code

    return render_template('callback.html', code = code, state = state)

@svr.route("/exchange")
def exchange() :
    return callTokenEndpoint('authorization_code')


@svr.route("/displayTokens")
def displayTokens() :
    access_token, access_token_expiry_time = extractTokenAndExpiryFromSession('access_token')
    id_token, id_token_expiry_time = extractTokenAndExpiryFromSession('id_token')
    refresh_token, refresh_token_expiry_time = extractTokenAndExpiryFromSession('refresh_token')

    return render_template('displayTokens.html', access_token = access_token, access_token_expiry = access_token_expiry_time, id_token = id_token, id_token_expiry = id_token_expiry_time, refresh_token = refresh_token, refresh_token_expiry = refresh_token_expiry_time)

@svr.route("/login")
def login() :
    redirectUrl = createAuthorizePath()
    print(redirectUrl)
    return redirect(redirectUrl)

@svr.route("/logout")
def logout() :
    params = {
        'client_id': CLIENT_ID,
        'id_token_hint' : session['id_token'],
        'returnTo': "/"
    }

    makeGETCall(IDP_DOMAIN, LOGOUT_PATH, '', params)
    session.clear()
    return redirect("/")

@svr.route("/refresh")
def refresh() :
    return callTokenEndpoint('refresh_token')

@svr.route("/userinfo")
def userinfo() :
    accessToken = session['access_token']

    if ('access_token' not in session) :
        return 'ERROR: No access token in session'

    headers = {'Authorization' : 'Bearer {}'.format(accessToken)}
    return makeGETCall(IDP_DOMAIN, USERINFO_PATH, headers, '')
 
@svr.route("/contactEndpoint")
def callContactEndpoint() :
    return callExternalEndpoint(CONTACT_CLIENT_ID, CONTACT_SECRET, CONTACT_PATH)

@svr.route("/consentEndpoint")
def callConsentlEndpoint() :
    return callExternalEndpoint(CONSENT_CLIENT_ID, CONSENT_SECRET, CONSENT_PATH)

def extractTokenAndExpiryFromSession(tokenName) :
    if tokenName in session :
        token = session[tokenName]
        try :
            token_claims = jwt.decode(token, options={"verify_signature": False})
            token_expiry_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(token_claims['exp']))
        except Exception as e:
            token_expiry_time  = "Unable to decode token. Not a JWT?"
    else :
        token = 'No token present'
        token_expiry_time = ''

    return token, token_expiry_time

def callExternalEndpoint(clientid, clientsecret, path) :
    
    if ('access_token' not in session) :
        return 'ERROR: No access token in session'

    accessToken = session['access_token']
    
    headers = {'Authorization' : 'Bearer {}'.format(accessToken),
            'CLIENT_ID'         : clientid,
            'CLIENT_SECRET'     : clientsecret
    }
    return makeGETCall(API_DOMAIN, path, headers, {})   

def makeGETCall(domain, path, headers, params) :
    
    url = urlunsplit(('https', domain, path, urlencode(params), ''))
    print('Making API call to: ' + url + ' with headers: ' + str(headers))

    r = requests.get(url, headers = headers)

    if(r.status_code != 200) :
        return r.text

    return r.json()

def createAuthorizePath() :

    code_verifier, code_challenge = pkce.generate_pkce_pair()

    session['code_verifier'] = code_verifier

    params = {
        'client_id': CLIENT_ID,
        'scope': SCOPE,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'state': svr.secret_key,
        'code_challenge' : code_challenge,
        'code_challenge_method' : 'S256'
    }
    return urlunsplit(('https', IDP_DOMAIN, AUTHORIZE_PATH, urlencode(params), ""))

def callTokenEndpoint(grant_type) :
    if(grant_type == 'authorization_code') :
        data = {'code'      : session['code'],  
        'client_id'     : CLIENT_ID,
        'client_secret' : CLIENT_SECRET,
        'redirect_uri'  : REDIRECT_URI,
        'grant_type'    : 'authorization_code',
        'code_verifier' : session['code_verifier']}
    if(grant_type == 'refresh_token') :
        data = {'refresh_token' : session['refresh_token'],  
            'client_id'     : CLIENT_ID,
            'client_secret' : CLIENT_SECRET,
            'redirect_uri'  : REDIRECT_URI,
            'grant_type'    : 'refresh_token'}

    url = urlunsplit(('https', IDP_DOMAIN, TOKEN_PATH, '', ''))
    r = requests.post(url, data = data)
    print(url)
    print(data)
    if(r.status_code != 200) :
        return(str(r.status_code) + ' ' + r.text)

    payload = json.loads(r.text)

    if 'access_token' in payload    : session['access_token'] = payload['access_token']
    if 'id_token' in payload        : session['id_token'] = id_token = payload['id_token']
    if 'refresh_token' in payload   : session['refresh_token'] = payload['refresh_token']

    return redirect(url_for('displayTokens'))

svr.run(debug=True, host="0.0.0.0", port=80)