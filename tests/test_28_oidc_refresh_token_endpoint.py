import json
import os

import pytest
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import RefreshAccessTokenRequest

from oidcendpoint.client_authn import ClientSecretBasic
from oidcendpoint.client_authn import ClientSecretJWT
from oidcendpoint.client_authn import ClientSecretPost
from oidcendpoint.client_authn import PrivateKeyJWT
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.refresh_token import RefreshAccessToken
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.session import setup_session
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

CAPABILITIES = {
    "response_types_supported": [" ".join(x) for x in RESPONSE_TYPES_SUPPORTED],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
    ],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
    "claim_types_supported": ["normal", "aggregated", "distributed"],
    "claims_parameter_supported": True,
    "request_parameter_supported": True,
    "request_uri_parameter_supported": True,
}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

REFRESH_TOKEN_REQ = RefreshAccessTokenRequest(
    grant_type="refresh_token", client_id="client_1", client_secret="hemligt"
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_config": {
                    "path": "{}/.well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "{}/registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {
                    "path": "{}/token",
                    "class": AccessToken,
                    "kwargs": {
                        "client_authn_method": {
                            "client_secret_basic": ClientSecretBasic,
                            "client_secret_post": ClientSecretPost,
                            "client_secret_jwt": ClientSecretJWT,
                            "private_key_jwt": PrivateKeyJWT,
                        }
                    },
                },
                "refresh_token": {
                    "path": "{}/token",
                    "class": RefreshAccessToken,
                    "kwargs": {
                        "client_authn_method": {
                            "client_secret_basic": ClientSecretBasic,
                            "client_secret_post": ClientSecretPost,
                            "client_secret_jwt": ClientSecretJWT,
                            "private_key_jwt": PrivateKeyJWT,
                        }
                    },
                },
                "userinfo": {
                    "path": "{}/userinfo",
                    "class": userinfo.UserInfo,
                    "kwargs": {"db_file": "users.json"},
                },
            },
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcendpoint.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "userinfo": {"class": UserInfo, "kwargs": {"db": {}}},
            "client_authn": verify_client,
            "template_dir": "template",
        }
        endpoint_context = EndpointContext(conf)
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.token_endpoint = endpoint_context.endpoint["token"]
        self.refresh_token_endpoint = endpoint_context.endpoint["refresh_token"]

    def test_init(self):
        assert self.refresh_token_endpoint

    def test_do_refresh_access_token(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "offline_access"]
        _cntx = self.token_endpoint.endpoint_context
        session_id = setup_session(
            _cntx, areq, uid="user", acr=INTERNETPROTOCOLPASSWORD
        )
        _cntx.sdb.update(session_id, user="diana")
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = _cntx.sdb[session_id]["code"]
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _req = self.refresh_token_endpoint.parse_request(_request.to_json())
        _resp = self.refresh_token_endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "id_token",
        }
        msg = self.refresh_token_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_do_2nd_refresh_access_token(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "offline_access"]
        _cntx = self.token_endpoint.endpoint_context
        session_id = setup_session(
            _cntx, areq, uid="user", acr=INTERNETPROTOCOLPASSWORD
        )
        _cntx.sdb.update(session_id, user="diana")
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = _cntx.sdb[session_id]["code"]
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _req = self.refresh_token_endpoint.parse_request(_request.to_json())
        _resp = self.refresh_token_endpoint.process_request(request=_req)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _req = self.refresh_token_endpoint.parse_request(_request.to_json())
        _resp = self.refresh_token_endpoint.process_request(request=_req)

        assert set(_resp.keys()) == {"response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "id_token",
        }
        msg = self.refresh_token_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)
