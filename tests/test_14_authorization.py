import json

import os
import pytest
from requests import request
from urllib.parse import parse_qs, urlparse

from oicmsg.key_jar import build_keyjar
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oic import AuthorizationRequest

from oicsrv.oic.authorization import Authorization
from oicsrv.srv_info import SrvInfo
from oicsrv.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oicsrv.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYJAR = build_keyjar(KEYDEFS)[1]

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

AUTH_REQ_DICT = AUTH_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path('users.json')).read()))


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.endpoint = Authorization(KEYJAR)
        conf = {
            "base_url": "https://example.com",
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "jwks_uri": 'https://example.com/jwks.json',
            "endpoint": {
                'registration': 'registration',
                'authorization': 'authz',
                'token': 'token',
                'userinfo': 'userinfo'
            },
            # 'authz' : {'name': 'Implicit'},
            'authentication': [
                {
                    'acr': INTERNETPROTOCOLPASSWORD,
                    'name': 'NoAuthn',
                    'args': {'user': 'diana'}
                }
            ],
            'userinfo': USERINFO
        }
        self.srv_info = SrvInfo(conf, keyjar=KEYJAR, httplib=request)
        self.srv_info.cdb['client_1'] = {
            "client_secret": 'hemligt',
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            'token_endpoint_auth_method': 'client_secret_post',
            'response_types': ['code', 'token', 'code id_token', 'id_token']
        }

    def test_init(self):
        assert self.srv_info

    def test_parse(self):
        _req = self.endpoint.parse_request(AUTH_REQ_DICT, self.srv_info)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == set(AUTH_REQ.keys())

    def test_process_request(self):
        _req = self.endpoint.parse_request(AUTH_REQ_DICT, self.srv_info)
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        assert set(_resp.keys()) == {'response_args', 'fragment_enc',
                                     'return_uri', 'http_headers'}

    def test_do_response_code(self):
        _req = self.endpoint.parse_request(AUTH_REQ_DICT, self.srv_info)
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        msg = self.endpoint.do_response(self.srv_info, **_resp)
        assert isinstance(msg, dict)
        _msg = parse_qs(msg['response'])
        assert _msg
        part = urlparse(msg['response'])
        assert part.fragment == ''
        assert part.query
        _query = parse_qs(part.query)
        assert _query
        assert 'code' in _query


    def test_do_response_id_token_no_nonce(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req['response_type'] = 'id_token'
        _req = self.endpoint.parse_request(_orig_req, self.srv_info)
        # Missing nonce
        assert isinstance(_req, ErrorResponse)

    def test_do_response_id_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req['response_type'] = 'id_token'
        _orig_req['nonce'] = 'rnd_nonce'
        _req = self.endpoint.parse_request(_orig_req, self.srv_info)
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        msg = self.endpoint.do_response(self.srv_info, **_resp)
        assert isinstance(msg, dict)
        part = urlparse(msg['response'])
        assert part.query == ''
        assert part.fragment
        _frag_msg = parse_qs(part.fragment)
        assert _frag_msg
        assert 'id_token' in _frag_msg
        assert 'code' not in _frag_msg
        assert 'token' not in _frag_msg

    def test_do_response_id_token_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req['response_type'] = 'id_token token'
        _orig_req['nonce'] = 'rnd_nonce'
        _req = self.endpoint.parse_request(_orig_req, self.srv_info)
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        msg = self.endpoint.do_response(self.srv_info, **_resp)
        assert isinstance(msg, dict)
        part = urlparse(msg['response'])
        assert part.query == ''
        assert part.fragment
        _frag_msg = parse_qs(part.fragment)
        assert _frag_msg
        assert 'id_token' in _frag_msg
        assert 'code' not in _frag_msg
        assert 'access_token' in _frag_msg

    def test_do_response_code_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req['response_type'] = 'code token'
        _req = self.endpoint.parse_request(_orig_req, self.srv_info)
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        msg = self.endpoint.do_response(self.srv_info, **_resp)
        assert isinstance(msg, dict)
        part = urlparse(msg['response'])
        assert part.query == ''
        assert part.fragment
        _frag_msg = parse_qs(part.fragment)
        assert _frag_msg
        assert 'id_token' not in _frag_msg
        assert 'code' in _frag_msg
        assert 'access_token' in _frag_msg

    def test_do_response_code_id_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req['response_type'] = 'code id_token'
        _orig_req['nonce'] = 'rnd_nonce'
        _req = self.endpoint.parse_request(_orig_req, self.srv_info)
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        msg = self.endpoint.do_response(self.srv_info, **_resp)
        assert isinstance(msg, dict)
        part = urlparse(msg['response'])
        assert part.query == ''
        assert part.fragment
        _frag_msg = parse_qs(part.fragment)
        assert _frag_msg
        assert 'id_token' in _frag_msg
        assert 'code' in _frag_msg
        assert 'access_token' not in _frag_msg


    def test_do_response_code_id_token_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req['response_type'] = 'code id_token token'
        _orig_req['nonce'] = 'rnd_nonce'
        _req = self.endpoint.parse_request(_orig_req, self.srv_info)
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        msg = self.endpoint.do_response(self.srv_info, **_resp)
        assert isinstance(msg, dict)
        part = urlparse(msg['response'])
        assert part.query == ''
        assert part.fragment
        _frag_msg = parse_qs(part.fragment)
        assert _frag_msg
        assert 'id_token' in _frag_msg
        assert 'code' in _frag_msg
        assert 'access_token' in _frag_msg
