import json

import pytest
from oicmsg.key_jar import build_keyjar
from oicsrv.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from requests import request

from oicsrv.oic.provider_config import ProviderConfiguration
from oicsrv.srv_info import SrvInfo

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


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.endpoint = ProviderConfiguration(KEYJAR)
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
            "authentication": [{
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'NoAuthn',
                'args': {'user': 'diana'}
            }]
        }
        self.srv_info = SrvInfo(conf, keyjar=KEYJAR, httplib=request)

    def test_do_response(self):
        args = self.endpoint.process_request(self.srv_info)
        msg = self.endpoint.do_response(self.srv_info, args)
        assert isinstance(msg, dict)
        _msg = json.loads(msg['response'])
        assert _msg
        assert ('Content-type', 'application/json') in msg['http_headers']