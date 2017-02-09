import urlparse
import sys
import boto3
import botocore
import jwt
import datetime
import json
import jinja2

from base64 import urlsafe_b64decode, b64decode
from Crypto.Util.number import bytes_to_long
from Crypto.PublicKey import RSA
from chalice import Chalice


app = Chalice(app_name='lemputer-auth')

idp_client = boto3.client('cognito-idp')
s3_client = boto3.client('s3', region_name="eu-west-1")

cognito_pool_id = "eu-west-1_MGtYSsW3S"
cognito_app_id = "28n5vtjaeso7cl89m8d522t5dv"
s3_bucket = "lemputer"

auth_parameters_template = {"UserPoolId": None,
                           "ClientId": None,
                           "AuthParameters": {"USERNAME": None,
                                              "PASSWORD": None}}


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


def _get_user_attributes(client, userpool_id, username):
    try:
        response = client.admin_get_user(Username=username,
                                         UserPoolId=userpool_id)

        return(True, response['UserAttributes'])

    except:
        return(False, str(sys.exc_info()[1]))


def set_user_attribute(client, userpool_id, username, attrib_name, attrib_value):
    try:
        response = client.admin_update_user_attributes(Username=username,
                                                       UserPoolId=userpool_id,
                                                       UserAttributes=[{'Name': attrib_name,
                                                                        'Value': attrib_value}])
        return(True, None)

    except:
        return(False, str(sys.exc_info()[1]))


def has_attribute(client, userpool_id, username, attribute="email"):
    result, data = _get_user_attributes(client, userpool_id, username)

    if result:
        for item in data:
            if item['Name'] == attribute:
                return(True, item['Value'])

        return(False, None)

    else:
        return(result, data)


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


def render_s3_template(client, bucket, template_name, content=None):
    # If no conent is supplied, set to empty dict
    if content is None:
        content = dict()

    file_object = s3_client.get_object(Bucket=bucket, Key=template_name)
    file_content = file_object['Body'].read()
    rendered_html = jinja2.Environment().from_string(file_content).render(content)

    return(rendered_html)


@app.route('/authform')
def auth_form():
    style_css = render_s3_template(s3_client, s3_bucket, "style.css")
    login_form = render_s3_template(s3_client, s3_bucket, "form_login.tmpl")
    return {'title': 'Lemputer - Auth',
            'style': style_css,
            'body': login_form}


@app.route('/authin', methods=['POST'], 
           content_types=['application/x-www-form-urlencoded'])
def auth_in():
    style_css = render_s3_template(s3_client, s3_bucket, "style.css")
    login_form = render_s3_template(s3_client, s3_bucket, "form_login.tmpl")
    new_password_form = render_s3_template(s3_client, s3_bucket, "form_newpassword.tmpl")
    reset_password_form = render_s3_template(s3_client, s3_bucket, "form_passwordreset.tmpl")
    login_success = render_s3_template(s3_client, s3_bucket, "loginsuccess.tmpl")

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
                        'style': style_css,
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
                            'style': style_css,
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
                            'style': style_css,
                            'body': reset_password_form,
                            'username': 'username=' + username + ';' +
                                        'expires=' + tomorrow + ';' +
                                        'path=/dev'}

        else:
            error_message = "Sorry, something went wrong. Please try again"
            login_form = render_s3_template(s3_client, s3_bucket, "form_login.tmpl", {"error_message": error_message})

            return {'title': 'Lemputer - Auth',
                    'style': style_css,
                    'body': login_form,
                    'access_token': 'access='}

    except:
        error_message = "Sorry, something went wrong. Please try again" + str(sys.exc_info()[1])
        login_form = render_s3_template(s3_client, s3_bucket, "form_login.tmpl", {"error_message": error_message})

        return {'title': 'Lemputer - Auth',
                'style': style_css,
                'body': login_form,
                'access_token': 'access='}


@app.route('/newpass', methods=['POST'], 
           content_types=['application/x-www-form-urlencoded'])
def auth_new_password():
    style_css = render_s3_template(s3_client, s3_bucket, "style.css")

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

            login_success = render_s3_template(s3_client, s3_bucket, "loginsuccess.tmpl")

            return {'title': 'Lemputer - Auth',
                    'style': style_css,
                    'body': login_success,
                    'username': 'username=' + username + ';' +
                                'expires=' + tomorrow + ';' +
                                'path=/dev',
                    'session_id': 'session=',
                    'access_token': 'access=' + access_token + ';' +
                                    'expires=' + tomorrow + ';' +
                                    'path=/dev'}

        else:
            error_message = "Sorry, something went wrong. Please try again"
            login_form = render_s3_template(s3_client, s3_bucket, "form_login.tmpl", {"error_message": error_message})

            return {'title': 'Lemputer - Auth',
                    'style': style_css,
                    'body': login_form,
                    'access_token': 'access='}

    except:
        return {'title': 'Lemputer - Auth',
                'style': style_css,
                'body': str(sys.exc_info()[1])}


@app.route('/resetpass', methods=['POST'], 
           content_types=['application/x-www-form-urlencoded'])
def auth_reset_password():
    style_css = render_s3_template(s3_client, s3_bucket, "style.css")

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

        error_message = "Your password has been reset."
        login_form = render_s3_template(s3_client, s3_bucket, "form_login.tmpl", {"error_message": error_message})

        return {'title': 'Lemputer - Auth',
                'style': style_css,
                'body': login_form}

    except:
        return {'title': 'Lemputer - Auth',
                'style': style_css,
                'body': str(sys.exc_info()[1])}


@app.route('/read')
def read_cookie():
    style_css = render_s3_template(s3_client, s3_bucket, "style.css")

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

        values = dict()
        if result:
            if 'username' in data:
                values['username'] = data['username']

                # Get admin group membership
                result, admin_user = is_admin(idp_client,
                                              cognito_pool_id,
                                              data['username'],
                                              admin_group="test")
                if admin_user:
                    values['is_admin'] = "True"
                else:
                    values['is_admin'] = "False"

                # Get lemputer name
                attrib_name = "custom:lemputer"
                result, attrib_value = has_attribute(idp_client,
                                                     cognito_pool_id,
                                                     data['username'],
                                                     attribute=attrib_name)

                if attrib_value is not None:
                    values['lemputer'] = attrib_value
                else:
                    values['lemputer'] = "Not Set"

                html_content = render_s3_template(s3_client, s3_bucket, "userinfo.tmpl", values)

        else:
            html_content = "Ooops, something went wrong!"

        return {'title': 'Lemputer - Auth',
                'style': style_css,
                'body': html_content}

    except:
        error_message = "You don't appear to be logged in.<br><br>" + str(sys.exc_info()[1])
        login_form = render_s3_template(s3_client, s3_bucket, "form_login.tmpl", {"error_message": error_message})

        return {'title': 'Lemputer - Auth',
                'style': style_css,
                'body': login_form}


@app.route('/clear')
def clear_cookie():
    error_message = "You're now logged out."
    login_form = render_s3_template(s3_client, s3_bucket, "form_login.tmpl", {"error_message": error_message})

    return {'title': 'Lemputer - Auth',
            'body': login_form,
            'access_token': 'access=',
            'session_id': 'session=',
            'username': 'username='}

