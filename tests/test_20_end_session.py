import json
import os
from http.cookies import SimpleCookie

import pytest

from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar
from oidcmsg.time_util import in_a_while


from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import TokenErrorResponse

from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.session import Session
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc import userinfo
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo

ISS = "https://example.com/"

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]

KEYJAR = build_keyjar(KEYDEFS)
KEYJAR.import_jwks(KEYJAR.export_jwks(private=True, issuer=''), issuer=ISS)

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
                                redirect_uri='{}cb'.format(ISS),
                                scope=['openid'],
                                state='STATE',
                                response_type='code')

AUTH_REQ_DICT = AUTH_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path('users.json')).read())


class SimpleCookieDealer(object):
    def __init__(self, name=''):
        self.name = name

    def create_cookie(self, value, typ, **kwargs):
        cookie = SimpleCookie()
        timestamp = str(utc_time_sans_frac())

        _payload = "::".join([value, timestamp, typ])

        bytes_load = _payload.encode("utf-8")
        bytes_timestamp = timestamp.encode("utf-8")

        cookie_payload = [bytes_load, bytes_timestamp]
        cookie[self.name] = (b"|".join(cookie_payload)).decode('utf-8')
        try:
            ttl = kwargs['ttl']
        except KeyError:
            pass
        else:
            cookie[self.name]["expires"] = in_a_while(seconds=ttl)
        return cookie

    def get_cookie_value(self, cookie=None, cookie_name=None):
        if not cookie_name:
            cookie_name = self.name

        if cookie is None or cookie_name is None:
            return None
        else:
            try:
                info, timestamp = cookie[cookie_name].value.split('|')
            except (TypeError, AssertionError):
                return None
            else:
                value = info.split("::")
                if timestamp == value[1]:
                    return value
        return None


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISS,
            "password": "mycket hemlig zebra",
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
                    },
                'session': {
                    'path': '{}/end_session',
                    'class': Session,
                    'kwargs': {}
                    }

                },
            "authentication": [{
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'NoAuthn',
                'kwargs': {'user': 'diana'}
                }],
            "userinfo": {
                'class': UserInfo,
                'kwargs': {'db': USERINFO_db}
                },
            'template_dir': 'template'
            }
        endpoint_context = EndpointContext(conf, keyjar=KEYJAR,
                                           cookie_dealer=SimpleCookieDealer(
                                               'oidc_op'))
        endpoint_context.cdb['client_1'] = {
            "client_secret": 'hemligt',
            "redirect_uris": [("{}cb".format(ISS), None)],
            "client_salt": "salted",
            'token_endpoint_auth_method': 'client_secret_post',
            'response_types': ['code', 'token', 'code id_token', 'id_token'],
            'post_logout_redirect_uris': [('{}logout_cb'.format(ISS), None)]
            }
        self.authn_endpoint = Authorization(endpoint_context)
        self.session_endpoint = Session(endpoint_context)
        self.token_endpoint = AccessToken(endpoint_context)

    def test_authn_then_end_with_state(self):
        _req = self.authn_endpoint.parse_request(AUTH_REQ_DICT)
        _authn_resp = self.authn_endpoint.process_request(_req)
        msg = self.authn_endpoint.do_response(**_authn_resp)
        assert isinstance(msg, dict)
        _req = self.session_endpoint.parse_request({
            'state': 'STATE',
            'post_logout_redirect_uri': '{}logout_cb'.format(ISS)
            })

        _resp = self.session_endpoint.process_request(_req,
                                                      cookie=msg['cookie'])
        assert _resp['response_args'] == '{}logout_cb?state=STATE'.format(ISS)
        _resp = self.session_endpoint.do_response(request=_req, **_resp)
        assert _resp
        # Trying to use 'code' after logout
        _code = _authn_resp['response_args']['code']
        _token_request = {
            'client_id': 'client_1',
            'redirect_uri': '{}cb'.format(ISS),
            "state": 'STATE',
            "grant_type": 'authorization_code',
            "client_secret": 'hemligt',
            'code': _code
        }
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(_req)
        assert isinstance(_resp, TokenErrorResponse)
        assert _resp['error'] == 'invalid_request'

    def test_authn_then_end_with_id_token(self):
        _req = self.authn_endpoint.parse_request(AUTH_REQ_DICT)
        _authn_resp = self.authn_endpoint.process_request(_req)
        msg = self.authn_endpoint.do_response(**_authn_resp)
        assert isinstance(msg, dict)
        _sid = self.authn_endpoint.endpoint_context.sdb.get_sid_by_kv(
            'state', 'STATE')
        session = self.authn_endpoint.endpoint_context.sdb[_sid]
        # Create ID Token
        _id_info = {'sub': session['sub']}
        _jwt = JWT(key_jar=self.authn_endpoint.endpoint_context.keyjar,
                   iss=self.authn_endpoint.endpoint_context.issuer,
                   lifetime=3600)
        _id_token = _jwt.pack(_id_info,
                              owner=self.authn_endpoint.endpoint_context.issuer,
                              recv='client_id')
        _req = self.session_endpoint.parse_request({
            'id_token_hint': _id_token,
            'post_logout_redirect_uri': '{}logout_cb'.format(ISS)
            })
        _resp = self.session_endpoint.process_request(_req,
                                                      cookie=msg['cookie'])
        assert _resp['response_args'] == '{}logout_cb'.format(ISS)
        _resp = self.session_endpoint.do_response(request=_req, **_resp)
        assert _resp
        # Trying to use 'code' after logout
        _code = _authn_resp['response_args']['code']
        _token_request = {
            'client_id': 'client_1',
            'redirect_uri': '{}cb'.format(ISS),
            "state": 'STATE',
            "grant_type": 'authorization_code',
            "client_secret": 'hemligt',
            'code': _code
        }
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)
        assert isinstance(_resp, TokenErrorResponse)
        assert _resp['error'] == 'invalid_request'
