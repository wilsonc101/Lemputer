import urlparse
import sys
import boto3
import botocore
import jwt
import datetime

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
        access_token = cookie_data.split("=")[1]
        token_data = jwt.decode(access_token, verify=False)

        user_name = token_data['username']
        token_expiry = datetime.datetime.fromtimestamp(token_data['exp']).strftime("%a, %d %b %Y %H:%M:%S GMT")
        token_issued = datetime.datetime.fromtimestamp(token_data['iat']).strftime("%a, %d %b %Y %H:%M:%S GMT")

        return {'title': 'Lemputer - Auth',
                'body': 'User - ' + user_name + ' --- expires - ' + token_expiry}

    except:
        return {'title': 'Lemputer - Auth',
                'body': login_form + "<br><br><b>You don't appear to be logged in.</b>"}


@app.route('/clear')
def clear_cookie():
    return {'title': 'Lemputer - Auth',
            'body': login_form + "<br><br><b>You've been logged out.</b>",
            'access_token': 'access=',
            'session_id': 'session=',
            'username': 'username='}
