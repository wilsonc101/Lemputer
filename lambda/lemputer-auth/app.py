import urlparse
import sys
import boto3
import botocore
import jwt
import datetime
import json

from base64 import urlsafe_b64decode, b64decode
from Crypto.Util.number import bytes_to_long
from Crypto.PublicKey import RSA
from chalice import Chalice

app = Chalice(app_name='lemputer-auth')

idp_client = boto3.client('cognito-idp')
cognito_pool_id = "eu-west-1_MGtYSsW3S"
cognito_app_id = "28n5vtjaeso7cl89m8d522t5dv"

auth_parameters_template = {"UserPoolId": None,
                           "ClientId": None,
                           "AuthParameters": {"USERNAME": None,
                                              "PASSWORD": None}}

login_form = """<form action="/dev/authin" method="POST">
<label><b>Username</b></label>
<input type="text" placeholder="Enter Username" name="username" required>
<br>
<label><b>Password</b></label>
<input type="password" placeholder="Enter Password" name="password" required>
<button type="submit">Login</button>
</form>"""

reset_password_form = """<b>You must provide a new password along with your verification code delivered via SMS or email.</b><br><br>
<form action="/dev/resetpass" method="POST">
<label><b>Verification Code</b></label>
<input type="text" placeholder="Enter Code" name="code" required>
<br>
<label><b>New Password</b></label>
<input type="password" placeholder="Enter Password" name="password" required>
<button type="submit">Login</button>
</form>"""

new_password_form = """<b>Your password has expired.</b><br><br>
<form action="/dev/newpass" method="POST">
<label><b>New Password</b></label>
<input type="password" placeholder="Enter Password" name="password" required>
<button type="submit">Login</button>
</form>"""


login_success = "<b>You're now logged in</b>"

tomorrow = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")

def _base64_pad(s):
    return (s + '=' * (4 - len(s) % 4))


def get_token_data(jwk_sets, token):
    # Get token segements and elements
    header, payload, signature = str(token).split(".")
    header_str = urlsafe_b64decode(header)
    header_json = json.loads(header_str, 'utf-8')

    kid = header_json['kid']
    alg = header_json['alg']

    # Find matching kid and algorithm, then verify
    for jwks in jwk_sets['keys']:
        if (jwks['kid'] == kid and jwks['alg'] == alg):
            e_b64 = _base64_pad(jwks['e'])
            n_b64 = _base64_pad(jwks['n'])

            e_bytes = urlsafe_b64decode(e_b64)
            n_bytes = urlsafe_b64decode(n_b64)

            modulus = bytes_to_long(e_bytes)
            exponant = bytes_to_long(n_bytes)

            public_key = RSA.construct((exponant, modulus))
            public_key_pem = public_key.publickey().exportKey()
    try:

                token_data = jwt.decode(token, key=public_key_pem, algorithms=[alg])
                return(True, token_data)

    except:
        return(False, str(sys.exc_info()[1]))


def set_new_password(client, session_id,
                     auth_parameters, new_password,
                     challenge_name="NEW_PASSWORD_REQUIRED"):

    response = client.admin_respond_to_auth_challenge(ChallengeName=challenge_name,
                                                      ClientId=auth_parameters['ClientId'],
                                                      UserPoolId=auth_parameters['UserPoolId'],
                                                      Session=session_id,
                                                      ChallengeResponses={'NEW_PASSWORD': new_password,
                                                                          'USERNAME': auth_parameters['AuthParameters']['USERNAME']})

    return response


def reset_password(client, cognito_app_id,
                   username, verification_code, new_password):

    try:
        response = client.confirm_forgot_password(ClientId=cognito_app_id,
                                                  Username=username,
                                                  ConfirmationCode=verification_code,
                                                  Password=new_password)
        return response

    except:
        return False


def do_login(client, auth_parameters, auth_flow="ADMIN_NO_SRP_AUTH"):

    try:
        response = client.admin_initiate_auth(AuthFlow=auth_flow,
                                              ClientId=auth_parameters['ClientId'],
                                              UserPoolId=auth_parameters['UserPoolId'],
                                              AuthParameters=auth_parameters['AuthParameters'])
        return(True, response)


    except botocore.exceptions.ClientError as e:
        error_code =  e.response['Error']['Code']

        if error_code == "PasswordResetRequiredException":
            # Login was accepted but a new password is required
            return(True, {"ChallengeName": "PASSWORD_RESET_REQUIRED"})

        else:
            # Login seems to have been accepted but returned an unknown code
            return(False, str(sys.exc_info()[1]))

    except:
        return(False, str(sys.exc_info()[1]))


def _get_user_groups(client, userpool_id, username):
    try:
        response = client.admin_list_groups_for_user(Username=username,
                                                     UserPoolId=userpool_id)

        return(True, response['Groups'])

    except:
        return(False, sys.exc_info()[1])


def is_admin(client, userpool_id, username, admin_group="admin"):
    result, data = _get_user_groups(client, userpool_id, username)

    if result:
        admin_user = False
        for group in data:
            if group['GroupName'] == admin_group:
                admin_user = True

        return(result, admin_user)

    else:
        return(result, data)



@app.route('/authform')
def auth_form():
    return {'title': 'Lemputer - Auth',
            'body': login_form}


@app.route('/authin', methods=['POST'], 
           content_types=['application/x-www-form-urlencoded'])
def auth_in():
    parsed = urlparse.parse_qs(app.current_request.raw_body)
    username = parsed['username'][0]
    password = parsed['password'][0]

    auth_params = auth_parameters_template
    auth_params['UserPoolId'] = cognito_pool_id
    auth_params['ClientId'] = cognito_app_id
    auth_params['AuthParameters']['USERNAME'] = username
    auth_params['AuthParameters']['PASSWORD'] = password

    try:
        login_response = do_login(idp_client, auth_params)

        if login_response[0] is True:
            # User account is functional - return tokens
            if "ChallengeName" not in login_response[1]:
                login_response = login_response[1]

                access_token = login_response['AuthenticationResult']['AccessToken']
                refresh_token = login_response['AuthenticationResult']['RefreshToken']
                id_token = login_response['AuthenticationResult']['IdToken']

                return {'title': 'Lemputer - Auth',
                        'body': login_success,
                        'username': 'username=' + username + ';' +
                                      'expires=' + tomorrow + ';' +
                                      'path=/dev',
                        'access_token': 'access=' + access_token + ';' +
                                        'expires=' + tomorrow + ';' +
                                        'path=/dev'}

            else:
                ## Authentication returned a challenge
                if login_response[1]['ChallengeName'] == "NEW_PASSWORD_REQUIRED":
                # New required (because a temporary password is set)
                    session_id = login_response[1]['Session']
                    return {'title': 'Lemputer - Auth',
                            'body': new_password_form,
                            'session_id': 'session=' + session_id + ';' +
                                          'expires=' + tomorrow + ';' +
                                          'path=/dev',
                            'username': 'username=' + username + ';' +
                                        'expires=' + tomorrow + ';' +
                                        'path=/dev'}

                elif login_response[1]['ChallengeName'] == "PASSWORD_RESET_REQUIRED":
                # Password reset required - no session cookie present
                    return {'title': 'Lemputer - Auth',
                            'body': reset_password_form,
                            'username': 'username=' + username + ';' +
                                        'expires=' + tomorrow + ';' +
                                        'path=/dev'}

        else:
            return {'title': 'Lemputer - Auth',
                    'body': login_form + '<br><br><b>Sorry, something went wrong logging you in. Please try again.</b><br><br><hr>' + login_response[1],
                    'access_token': 'access='}

    except:
        return {'title': 'Lemputer - Auth',
                'body': login_form + '<br><br><b>Sorry, there was an error logging you in. Please try again.</b><br><br><hr>' + str(sys.exc_info()[1]),
                'access_token': 'access='}


@app.route('/newpass', methods=['POST'], 
           content_types=['application/x-www-form-urlencoded'])
def auth_new_password():
    try:
        # Extract cookie data
        cookie_data = app.current_request.headers['cookie']
        for cookie in cookie_data.split("; "):
            cookie_name = cookie.split("=")[0]
            cookie_content = cookie.split("=")[1]
            if cookie_name == "access":
                access_token = cookie_content
            elif cookie_name == "username":
                username = cookie_content
            elif cookie_name == "session":
                session_id = cookie_content

        # Extract HTML form data
        parsed = urlparse.parse_qs(app.current_request.raw_body)
        password = parsed['password'][0]

        auth_params = auth_parameters_template
        auth_params['UserPoolId'] = cognito_pool_id
        auth_params['ClientId'] = cognito_app_id
        auth_params['AuthParameters']['USERNAME'] = username
        auth_params['AuthParameters']['PASSWORD'] = password

        response = set_new_password(idp_client, session_id, auth_params, password)
        if "ChallengeName" not in response:
            access_token = response['AuthenticationResult']['AccessToken']
            refresh_token = response['AuthenticationResult']['RefreshToken']
            id_token = response['AuthenticationResult']['IdToken']

            return {'title': 'Lemputer - Auth',
                    'body': login_success,
                    'username': 'username=' + username + ';' +
                                'expires=' + tomorrow + ';' +
                                'path=/dev',
                    'session_id': 'session=',
                    'access_token': 'access=' + access_token + ';' +
                                    'expires=' + tomorrow + ';' +
                                    'path=/dev'}

        else:
            return {'title': 'Lemputer - Auth',
                    'body': login_form + '<br><br><b>Sorry, something went wrong logging you in. Please try again.</b>',
                    'access_token': 'access='}

    except:
        return {'title': 'Lemputer - Auth',
                'body': str(sys.exc_info()[1])}


@app.route('/resetpass', methods=['POST'], 
           content_types=['application/x-www-form-urlencoded'])
def auth_reset_password():
    # Extract cookie data
    cookie_data = app.current_request.headers['cookie']
    for cookie in cookie_data.split("; "):
        cookie_name = cookie.split("=")[0]
        cookie_content = cookie.split("=")[1]
        if cookie_name == "access":
            access_token = cookie_content
        elif cookie_name == "username":
            username = cookie_content
        elif cookie_name == "session":
            session_id = cookie_content

    # Extract HTML form data
    parsed = urlparse.parse_qs(app.current_request.raw_body)
    password = parsed['password'][0]
    verification_code = parsed['code'][0]

    try:
        response = reset_password(idp_client, cognito_app_id, username, verification_code, password)
        assert response, "error reseting password"

        return {'title': 'Lemputer - Auth',
                'body': login_form + '<br><br><b>Your password has been reset.</b>'}

    except:
        return {'title': 'Lemputer - Auth',
                'body': 'error -- ' + str(sys.exc_info()[1])}


@app.route('/read')
def read_cookie():
    try:
        cookie_data = app.current_request.headers['cookie']
        for cookie in cookie_data.split("; "):
            cookie_name = cookie.split("=")[0]
            cookie_content = cookie.split("=")[1]
            if cookie_name == "access":
                access_token = cookie_content
            elif cookie_name == "username":
                username = cookie_content
            elif cookie_name == "session":
                session_id = cookie_content

        jwk_sets = {"keys":[{"alg":"RS256",
                             "e":"AQAB",
                             "kid":"lgsLnMJM7xXhJ7m2ee0zVgjfONBQ8jxIJ2KwYRc+fl8=",
                             "kty":"RSA",
                             "n":"l6iOwQSvbiV-JxUWBYXtw4uPEdqbne9ttbfY4JbF4-3LRLTJYaQ8oNjCpFeVx_H66-extpAyybemZ3H2w5wx1rppyToezerdo9-WW2F2vsSEbLKR-3tEYsYjfFsE_mq7QLP24Y_Il5npeUu7KS7malqvviwU3E3EqcTaNWRULMcVlMKVqi3gt0VJ_QsEC6iS5mmmhlLaxo51APHtUmerdAKwlQPLo0I-rf0_BEUC4KohQYjh4YdZnqiYni_8xF4jJYQe9cD-TM8lV2WgxlgmHQhGfjrXAM7wvHoQE91WGP-tZ5qj4wBi3SBuPZ6MJJVxTDjjo-j2oDSuaK3NJurfow",
                             "use":"sig"},
                            {"alg":"RS256",
                             "e":"AQAB",
                             "kid":"Gqan94fSKgyihKi9dzQvHRmXHOAwjB0Nx/UcCGZ5wUo=",
                             "kty":"RSA",
                             "n":"pBeavjdnV1lbotXiIQs69Z8IL8vRomQBaRNht7K5GgsA75Jh6irXiRfK6wIPzVCWcnwRUNclKGAziTYeiaounKayqyUAEpemKhT8lXrbvSiuroWcnbUjr7dUruSyemS-gb7K3JdJHIdJ2ehSxVjAogI0GKFgecHNf0qO2TgHm0Weoj67ZUxYFzkLr_FqHCwr5fFbEiW3Ktxev9ZGjqRIYGiitca5C_oRuGKbQLIaPOTPwFpTUOVPwu5p2xdQyLuUM6zbS_TEaR7MJ0hq7IxRwKIZYeN85zIHDR22k_W7PSmNR-MP5RJqOfZL_Pg-U8V8UDg5cWI5h4Wp34DxIJGB-w",
                             "use":"sig"}]}

        result, data = get_token_data(jwk_sets, access_token)

        if result:
            if 'username' in data:
                result, admin_user = is_admin(idp_client,
                                              cognito_pool_id,
                                              data['username'],
                                              admin_group="test")
                if admin_user:
                    response_text = data['username'] + " is an admin"
                else:
                    response_text = data['username'] + " is NOT an admin"

        else:
            response_text = data



        return {'title': 'Lemputer - Auth',
                'body': response_text}


    except:
        return {'title': 'Lemputer - Auth',
                'body': login_form + "<br><br><b>You don't appear to be logged in.</b><br><br><br><hr><br><br>" + str(sys.exc_info()[1])}


@app.route('/clear')
def clear_cookie():
    return {'title': 'Lemputer - Auth',
            'body': login_form + "<br><br><b>You've been logged out.</b>",
            'access_token': 'access=',
            'session_id': 'session=',
            'username': 'username='}
