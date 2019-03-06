import base64

from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import build_keyjar
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode

from oidcendpoint import JWT_BEARER
from oidcendpoint.client_authn import ClientSecretBasic
from oidcendpoint.client_authn import ClientSecretJWT
from oidcendpoint.client_authn import ClientSecretPost
from oidcendpoint.client_authn import PrivateKeyJWT
from oidcendpoint.endpoint_context import EndpointContext

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYJAR = build_keyjar(KEYDEFS)

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "endpoint": {},
    'template_dir': 'template',
    'jwks':
        {
            'private_path': 'own/jwks.json',
            'key_defs': KEYDEFS,
            'uri_path': 'static/jwks.json'
        }
}
client_id = 'client_id'
client_secret = 'a_longer_client_secret'
# Need to add the client_secret as a symmetric key bound to the client_id
KEYJAR.add_symmetric(client_id, client_secret, ['sig'])

endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
endpoint_context.cdb[client_id] = {'client_secret': client_secret}


def test_client_secret_basic():
    _token = '{}:{}'.format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))

    authz_token = 'Basic {}'.format(token)

    authn_info = ClientSecretBasic(endpoint_context).verify({}, authz_token)

    assert authn_info['client_id'] == client_id


def test_client_secret_post():
    request = {'client_id': client_id, 'client_secret': client_secret}

    authn_info = ClientSecretPost(endpoint_context).verify(request)

    assert authn_info['client_id'] == client_id


def test_client_secret_jwt():
    client_keyjar = KeyJar()
    client_keyjar[conf['issuer']] = KEYJAR.issuer_keys['']
    # The only own key the client has a this point
    client_keyjar.add_symmetric('', client_secret, ['sig'])

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg='HS256')
    _assertion = _jwt.pack({'aud': [conf['issuer']]})

    request = {
        'client_assertion': _assertion,
        'client_assertion_type': JWT_BEARER
    }

    authn_info = ClientSecretJWT(endpoint_context).verify(request)

    assert authn_info['client_id'] == client_id
    assert 'jwt' in authn_info


def test_private_key_jwt():
    # Own dynamic keys
    client_keyjar = build_keyjar(KEYDEFS)
    # The servers keys
    client_keyjar[conf['issuer']] = KEYJAR.issuer_keys['']

    _jwks = client_keyjar.export_jwks()
    endpoint_context.keyjar.import_jwks(_jwks, client_id)

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg='RS256')
    _assertion = _jwt.pack({'aud': [conf['issuer']]})

    request = {
        'client_assertion': _assertion,
        'client_assertion_type': JWT_BEARER
    }

    authn_info = PrivateKeyJWT(endpoint_context).verify(request)

    assert authn_info['client_id'] == client_id
    assert 'jwt' in authn_info
