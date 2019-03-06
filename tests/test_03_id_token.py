import json
import os
import time

from cryptojwt.jws import jws
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import build_keyjar
from cryptojwt.key_jar import KeyJar
from oidcmsg.oidc import JsonWebToken, AuthorizationRequest
from oidcmsg.oidc import RegistrationResponse

from oidcendpoint.client_authn import verify_client
from oidcendpoint.id_token import sign_encrypt_id_token
from oidcendpoint.id_token import id_token_payload
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc import userinfo
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path('users.json')).read()))

AREQN = AuthorizationRequest(response_type="code", client_id="client1",
                             redirect_uri="http://example.com/authz",
                             scope=["openid"], state="state000",
                             nonce="nonce")

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    'jwks':
        {
            'key_defs': KEYDEFS,
            'uri_path': 'static/jwks.json'
        },
    "jwks_uri": 'https://example.com/jwks.json',
    'endpoint': {
        'authorization_endpoint': {
            'path': '{}/authorization',
            'class': Authorization,
            'kwargs': {}
            },
        'token_endpoint': {
            'path': '{}/token',
            'class': AccessToken,
            'kwargs': {}
            },
        'userinfo_endpoint': {
            'path': '{}/userinfo',
            'class': userinfo.UserInfo,
            'kwargs': {'db_file': 'users.json'}
            }
        },
    'client_authn': verify_client,
    'template_dir': 'template'
    }

ENDPOINT_CONTEXT = EndpointContext(conf)
ENDPOINT_CONTEXT.cdb['client_1'] = {
    "client_secret": 'hemligt',
    "redirect_uris": [("https://example.com/cb", None)],
    "client_salt": "salted",
    'token_endpoint_auth_method': 'client_secret_post',
    'response_types': ['code', 'token', 'code id_token', 'id_token']
    }


def test_id_token_payload_0():
    session_info = {'authn_req': AREQN, 'sub': '1234567890'}

    info = id_token_payload(session_info)
    assert info['payload'] == {
        'acr': '2', 'sub': '1234567890', 'nonce': 'nonce'
    }
    assert info['lifetime'] == 300


def test_id_token_payload_1():
    session_info = {'authn_req': AREQN, 'sub': '1234567890'}

    info = id_token_payload(session_info)
    assert info['payload'] == {
        'acr': '2', 'nonce': 'nonce',
        'sub': '1234567890'
    }
    assert info['lifetime'] == 300


def test_id_token_payload_with_code():
    session_info = {'authn_req': AREQN, 'sub': '1234567890'}

    info = id_token_payload(session_info, code='ABCDEFGHIJKLMNOP')
    assert info['payload'] == {
        'acr': '2', 'nonce': 'nonce',
        'c_hash': '5-i4nCch0pDMX1VCVJHs1g',
        'sub': '1234567890'
    }
    assert info['lifetime'] == 300


def test_id_token_payload_with_access_token():
    session_info = {'authn_req': AREQN, 'sub': '1234567890'}

    info = id_token_payload(session_info, access_token='012ABCDEFGHIJKLMNOP')
    assert info['payload'] == {
        'acr': '2', 'nonce': 'nonce',
        'at_hash': 'bKkyhbn1CC8IMdavzOV-Qg',
        'sub': '1234567890'
    }
    assert info['lifetime'] == 300


def test_id_token_payload_with_code_and_access_token():
    session_info = {'authn_req': AREQN, 'sub': '1234567890'}

    info = id_token_payload(session_info, access_token='012ABCDEFGHIJKLMNOP',
                            code='ABCDEFGHIJKLMNOP')
    assert info['payload'] == {
        'acr': '2', 'nonce': 'nonce',
        'at_hash': 'bKkyhbn1CC8IMdavzOV-Qg',
        'c_hash': '5-i4nCch0pDMX1VCVJHs1g',
        'sub': '1234567890'
    }
    assert info['lifetime'] == 300


def test_id_token_payload_with_userinfo():
    session_info = {'authn_req': AREQN, 'sub': '1234567890'}

    info = id_token_payload(session_info, user_info={'given_name': 'Diana'})
    assert info['payload'] == {
        'acr': '2', 'nonce': 'nonce',
        'given_name': 'Diana', 'sub': '1234567890'
    }
    assert info['lifetime'] == 300


def test_id_token_payload_many_0():
    session_info = {'authn_req': AREQN, 'sub': '1234567890'}

    info = id_token_payload(session_info, user_info={'given_name': 'Diana'},
                            access_token='012ABCDEFGHIJKLMNOP',
                            code='ABCDEFGHIJKLMNOP')
    assert info['payload'] == {
        'acr': '2', 'nonce': 'nonce',
        'given_name': 'Diana',
        'at_hash': 'bKkyhbn1CC8IMdavzOV-Qg',
        'c_hash': '5-i4nCch0pDMX1VCVJHs1g',
        'sub': '1234567890'
    }
    assert info['lifetime'] == 300


def test_sign_encrypt_id_token():
    client_info = RegistrationResponse(
        id_token_signed_response_alg='RS512', client_id='client_1')
    session_info = {
        'authn_req': AREQN,
        'sub': 'sub',
        'authn_event': {
            "authn_info": 'loa2',
            "authn_time": time.time()
        }
    }

    ENDPOINT_CONTEXT.jwx_def["signing_alg"] = {'id_token': 'RS384'}
    ENDPOINT_CONTEXT.cdb['client_1'] = client_info.to_dict()

    _token = sign_encrypt_id_token(ENDPOINT_CONTEXT, session_info, 'client_1',
                                   sign=True)
    assert _token

    _jws = jws.factory(_token)

    assert _jws.jwt.headers['alg'] == 'RS512'

    client_keyjar = KeyJar()
    _jwks = ENDPOINT_CONTEXT.keyjar.export_jwks()
    client_keyjar.import_jwks(_jwks, ENDPOINT_CONTEXT.issuer)

    _jwt = JWT(key_jar=client_keyjar, iss='client_1')
    res = _jwt.unpack(_token)
    assert isinstance(res, dict)
    assert res['aud'] == ['client_1']
