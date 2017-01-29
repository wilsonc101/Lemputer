import boto3
import botocore
import json
import sys
import jwt

from base64 import urlsafe_b64decode, b64decode
from Crypto.Util.number import bytes_to_long
from Crypto.PublicKey import RSA
from chalice import Chalice

app = Chalice(app_name='lemputer-data')


def _base64_pad(s):
    return (s + '=' * (4 - len(s) % 4))


def get_token_data(jwk_sets, token):
    try:
        # Get token segements and elements
        header, payload, signature = str(token).split(".")

        header_str = urlsafe_b64decode(header)
        header_json = json.loads(header_str, 'utf-8')

        kid = header_json['kid']
        alg = header_json['alg']

        # Find matching kid and algorithm, then verify
        for jwks in jwk_sets['keys']:
            if (jwks['kid'] == kid and jwks['alg'] == alg):
                e_b64 = _base64_pad(jwks['e'] + "=")
                n_b64 = _base64_pad(jwks['n'] + "=")

                e_bytes = urlsafe_b64decode(e_b64)
                n_bytes = urlsafe_b64decode(n_b64)

                modulus = bytes_to_long(e_bytes)
                exponant = bytes_to_long(n_bytes)

                public_key = RSA.construct((exponant, modulus))
                public_key_pem = public_key.publickey().exportKey()

                token_data = jwt.decode(token, key=public_key_pem, algorithms=[alg])
                return token_data

    except:
        return(False, sys.exc_info()[1])


@app.route('/')
def index():
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


    return {'hello': 'world'}


# The view function above will return {"hello": "world"}
# whenever you make an HTTP GET request to '/'.
#
# Here are a few more examples:
#
# @app.route('/hello/{name}')
# def hello_name(name):
#    # '/hello/james' -> {"hello": "james"}
#    return {'hello': name}
#
# @app.route('/users', methods=['POST'])
# def create_user():
#     # This is the JSON body the user sent in their POST request.
#     user_as_json = app.json_body
#     # Suppose we had some 'db' object that we used to
#     # read/write from our database.
#     # user_id = db.create_user(user_as_json)
#     return {'user_id': user_id}
#
# See the README documentation for more examples.
#
