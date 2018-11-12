import json

import os
import pytest
import time

from cryptojwt.key_jar import build_keyjar

from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest

from oidcendpoint.client_authn import verify_client
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYJAR = build_keyjar(KEYDEFS)

RESPONSE_TYPES_SUPPORTED = [
    ["code"], ["token"], ["id_token"], ["code", "token"], ["code", "id_token"],
    ["id_token", "token"], ["code", "token", "id_token"], ['none']]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post", "client_secret_basic",
        "client_secret_jwt", "private_key_jwt"],
    "response_modes_supported": ['query', 'fragment', 'form_post'],
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code", "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer", "refresh_token"],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

AUTH_REQ = AuthorizationRequest(client_id='client_1',
                                redirect_uri='https://example.com/cb',
                                scope=['openid'],
                                state='STATE',
                                response_type='code')

TOKEN_REQ = AccessTokenRequest(client_id='client_1',
                               redirect_uri='https://example.com/cb',
                               state='STATE',
                               grant_type='authorization_code',
                               client_secret='hemligt')

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path('users.json')).read()))


def setup_session(endpoint_context, areq):
    authn_event = AuthnEvent(uid="uid", salt='salt',
                             authn_info=INTERNETPROTOCOLPASSWORD,
                             time_stamp=time.time())
    sid = endpoint_context.sdb.create_authz_session(authn_event, areq,
                                                    client_id='client_id')
    endpoint_context.sdb.do_sub(sid, '')
    return sid


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.endpoint = userinfo.UserInfo(KEYJAR)
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "jwks": {
                'url_path': '{}/jwks.json',
                'local_path': 'static/jwks.json',
                'private_path': 'own/jwks.json'
            },
            'endpoint': {
                'provider_config': {
                    'path': '{}/.well-known/openid-configuration',
                    'class': ProviderConfiguration,
                    'kwargs': {}
                },
                'registration': {
                    'path': '{}/registration',
                    'class': Registration,
                    'kwargs': {}
                },
                'authorization': {
                    'path': '{}/authorization',
                    'class': Authorization,
                    'kwargs': {}
                },
                'token': {
                    'path': '{}/token',
                    'class': AccessToken,
                    'kwargs': {}
                },
                'userinfo': {
                    'path': '{}/userinfo',
                    'class': userinfo.UserInfo,
                    'kwargs': {'db_file': 'users.json'}
                }
            },
            'client_authn': verify_client,
            "authentication": [{
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'NoAuthn',
                'kwargs': {'user': 'diana'}
            }],
            'template_dir': 'template'
        }
        endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
        endpoint_context.cdb['client_1'] = {
            "client_secret": 'hemligt',
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            'token_endpoint_auth_method': 'client_secret_post',
            'response_types': ['code', 'token', 'code id_token', 'id_token']
        }
        self.endpoint = userinfo.UserInfo(endpoint_context)

    def test_init(self):
        assert self.endpoint

    def test_parse(self):
        session_id = setup_session(self.endpoint.endpoint_context, AUTH_REQ)
        _dic = self.endpoint.endpoint_context.sdb.upgrade_to_token(
            key=session_id)
        _req = self.endpoint.parse_request(
            {}, auth="Bearer {}".format(_dic['access_token']))

        assert set(_req.keys()) == {'client_id', 'access_token'}
