import json
import pytest

from oidcmsg.key_jar import build_keyjar
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.oidc import RegistrationResponse

from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc import userinfo
from oidcendpoint.endpoint_context import EndpointContext

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

msg = {
    "application_type": "web",
    "redirect_uris": ["https://client.example.org/callback",
                      "https://client.example.org/callback2"],
    "client_name": "My Example",
    "client_name#ja-Jpan-JP": "クライアント名",
    "logo_uri": "https://client.example.org/logo.png",
    "subject_type": "pairwise",
    "token_endpoint_auth_method": "client_secret_basic",
    "jwks_uri": "https://client.example.org/my_public_keys.jwks",
    "userinfo_encrypted_response_alg": "RSA1_5",
    "userinfo_encrypted_response_enc": "A128CBC-HS256",
    "contacts": ["ve7jtb@example.org", "mary@example.org"],
    "request_uris": [
        "https://client.example.org/rf.txt"
        "#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
}

CLI_REQ = RegistrationRequest(**msg)


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        self.endpoint = Registration(KEYJAR)
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
            }
        }
        self.srv_info = EndpointContext(conf, keyjar=KEYJAR)

    def test_parse(self):
        _req = self.endpoint.parse_request(self.srv_info,CLI_REQ.to_json())

        assert isinstance(_req, RegistrationRequest)
        assert set(_req.keys()) == set(CLI_REQ.keys())

    def test_process_request(self):
        _req = self.endpoint.parse_request(self.srv_info, CLI_REQ.to_json())
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        _reg_resp = _resp['response_args']
        assert isinstance(_reg_resp, RegistrationResponse)
        assert 'client_id' in _reg_resp and 'client_secret' in _reg_resp

    def test_do_response(self):
        _req = self.endpoint.parse_request(self.srv_info, CLI_REQ.to_json())
        _resp = self.endpoint.process_request(srv_info=self.srv_info,
                                              request=_req)
        msg = self.endpoint.do_response(self.srv_info, **_resp)
        assert isinstance(msg, dict)
        _msg = json.loads(msg['response'])
        assert _msg
