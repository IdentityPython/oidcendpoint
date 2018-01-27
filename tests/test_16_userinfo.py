import json

import os
import pytest
import time
from requests import request

from oicmsg.key_jar import build_keyjar
from oicmsg.oic import AccessTokenRequest
from oicmsg.oic import AuthorizationRequest

from oicsrv.client_authn import verify_client
from oicsrv.oic import userinfo
from oicsrv.sdb import AuthnEvent
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


def setup_session(srv_info, areq):
    authn_event = AuthnEvent("uid", 'salt', authn_info=INTERNETPROTOCOLPASSWORD,
                             time_stamp=time.time())
    sid = srv_info.sdb.create_authz_session(authn_event, areq)
    srv_info.sdb.do_sub(sid, '')
    return sid


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.endpoint = userinfo.UserInfo(KEYJAR)
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
            'userinfo': USERINFO,
            'client_authn': verify_client
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
        session_id = setup_session(self.srv_info, AUTH_REQ)
        _dic = self.srv_info.sdb.upgrade_to_token(key=session_id)
        _req = self.endpoint.parse_request(
            '', self.srv_info, auth="Bearer {}".format(_dic['access_token']))

        assert isinstance(_req,)
    #     assert set(_req.keys()) == set(_token_request.keys())
    #
    # def test_process_request(self):
    #     session_id = setup_session(self.srv_info, AUTH_REQ)
    #     _token_request = TOKEN_REQ_DICT.copy()
    #     _token_request['code'] = self.srv_info.sdb[session_id]['code']
    #     self.srv_info.sdb.update(session_id, user='diana')
    #     _req = self.endpoint.parse_request(_token_request, self.srv_info)
    #
    #     _resp = self.endpoint.process_request(srv_info=self.srv_info,
    #                                           request=_req)
    #
    #     assert _resp
    #     assert set(_resp.keys()) == {'http_headers', 'response_args'}
    #
    # def test_do_response(self):
    #     session_id = setup_session(self.srv_info, AUTH_REQ)
    #     self.srv_info.sdb.update(session_id, user='diana')
    #     _token_request = TOKEN_REQ_DICT.copy()
    #     _token_request['code'] = self.srv_info.sdb[session_id]['code']
    #     _req = self.endpoint.parse_request(_token_request, self.srv_info)
    #
    #     _resp = self.endpoint.process_request(srv_info=self.srv_info,
    #                                           request=_req)
    #     msg = self.endpoint.do_response(self.srv_info, request=_req, **_resp)
    #     assert isinstance(msg, dict)

