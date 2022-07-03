from configparser import ConfigParser

CLIENT_ID       = 'CLIENT_ID'
CLIENT_SECRET   = 'CLIENT_SECRET'
SCOPE           = 'SCOPE'
REDIRECT_URI    = 'REDIRECT_URI'
IDP_DOMAIN      = 'IDP_DOMAIN'
AUTHORIZE_PATH  = 'AUTHORIZE_PATH'
LOGOUT_PATH     = "LOGOUT_PATH"
TOKEN_PATH      = 'TOKEN_PATH'
USERINFO_PATH   = "USERINFO_PATH"

config_object = ConfigParser()
config_object["IDP"] = {
    CLIENT_ID       : 'W5z7HlQslHkoQcVsKxokM1jYaijvtRfh',
    CLIENT_SECRET   : 'QeEMuF-9lYMlcKDOuKkrKGWU_gzRPYcpkoI8B0IHJKNHUHfrZ6yFTp2BN-whiPWo',
    SCOPE           : 'openid email profile',
    REDIRECT_URI    : 'http://localhost/callback',
    IDP_DOMAIN      : 'dev-siesgeoh.us.auth0.com',
    AUTHORIZE_PATH  : 'authorize',
    LOGOUT_PATH     : "v2/logout",
    TOKEN_PATH      : 'oauth/token',
    USERINFO_PATH   : "userinfo"
}

with open('config/auth0_personal.ini', 'w') as conf:
    config_object.write(conf)