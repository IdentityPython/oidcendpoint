import json

import pytest
from oidcmsg.key_jar import build_keyjar

from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.oidc.discovery import Discovery
from oidcendpoint.endpoint_context import EndpointContext

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYJAR = build_keyjar(KEYDEFS)[1]


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.endpoint = Discovery(KEYJAR)
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {},
            "authentication": [{
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'NoAuthn',
                'args': {'user': 'diana'}
            }]
        }
        self.srv_info = EndpointContext(conf, keyjar=KEYJAR)

    def test_do_response(self):
        args = self.endpoint.process_request(
            self.srv_info, request={'resource': 'acct:foo@example.com'})
        msg = self.endpoint.do_response(self.srv_info, **args)
        _resp = json.loads(msg['response'])
        assert _resp == {"subject": "acct:foo@example.com", "links": [
            {"href": "https://example.com/",
             "rel": "http://openid.net/specs/connect/1.0/issuer"}]}
