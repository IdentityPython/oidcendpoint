import json
import os

import pytest
from cryptojwt import JWT
from cryptojwt.key_jar import build_keyjar
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import RefreshAccessTokenRequest

from oidcendpoint import JWT_BEARER
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.exception import MultipleUsage
from oidcendpoint.exception import ProcessError
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token_coop import TokenCoop
from oidcendpoint.session import setup_session
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLIENT_KEYJAR = build_keyjar(KEYDEFS)

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
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
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
            "jwks": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "provider_config": {
                    "path": ".well-known/openid-configuration",
                    "class": ProviderConfiguration,
                    "kwargs": {},
                },
                "registration": {
                    "path": "registration",
                    "class": Registration,
                    "kwargs": {},
                },
                "authorization": {
                    "path": "authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {
                    "path": "token",
                    "class": TokenCoop,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_basic",
                            "client_secret_post",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
                "userinfo": {
                    "path": "userinfo",
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
            "endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        endpoint_context.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.endpoint = endpoint_context.endpoint["token"]

    def test_init(self):
        assert self.endpoint

    def test_parse(self):
        session_id = setup_session(self.endpoint.endpoint_context, AUTH_REQ, uid="user")
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = self.endpoint.endpoint_context.sdb[session_id]["code"]
        _req = self.endpoint.parse_request(_token_request)

        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == set(_token_request.keys())

    def test_process_request(self):
        session_id = setup_session(
            self.endpoint.endpoint_context,
            AUTH_REQ,
            uid="user",
            acr=INTERNETPROTOCOLPASSWORD,
        )
        _token_request = TOKEN_REQ_DICT.copy()
        _context = self.endpoint.endpoint_context
        _token_request["code"] = _context.sdb[session_id]["code"]
        _context.sdb.update(session_id, user="diana")
        _req = self.endpoint.parse_request(_token_request)

        _resp = self.endpoint.process_request(request=_req)

        assert _resp
        assert set(_resp.keys()) == {"http_headers", "response_args"}

    def test_process_request_using_code_twice(self):
        session_id = setup_session(
            self.endpoint.endpoint_context,
            AUTH_REQ,
            uid="user",
            acr=INTERNETPROTOCOLPASSWORD,
        )
        _token_request = TOKEN_REQ_DICT.copy()
        _context = self.endpoint.endpoint_context
        _token_request["code"] = _context.sdb[session_id]["code"]
        _context.sdb.update(session_id, user="diana")
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        # 2nd time used
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        assert _resp
        assert set(_resp.keys()) == {"error", "error_description"}

    def test_do_response(self):
        session_id = setup_session(
            self.endpoint.endpoint_context,
            AUTH_REQ,
            uid="user",
            acr=INTERNETPROTOCOLPASSWORD,
        )
        self.endpoint.endpoint_context.sdb.update(session_id, user="diana")
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = self.endpoint.endpoint_context.sdb[session_id]["code"]
        _req = self.endpoint.parse_request(_token_request)

        _resp = self.endpoint.process_request(request=_req)
        msg = self.endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_process_request_using_private_key_jwt(self):
        session_id = setup_session(
            self.endpoint.endpoint_context,
            AUTH_REQ,
            uid="user",
            acr=INTERNETPROTOCOLPASSWORD,
        )
        _token_request = TOKEN_REQ_DICT.copy()
        del _token_request["client_id"]
        del _token_request["client_secret"]
        _context = self.endpoint.endpoint_context

        _jwt = JWT(CLIENT_KEYJAR, iss=AUTH_REQ["client_id"], sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [_context.endpoint["token"].full_path]})
        _token_request.update({
                                  "client_assertion": _assertion,
                                  "client_assertion_type": JWT_BEARER
                              })
        _token_request["code"] = self.endpoint.endpoint_context.sdb[session_id]["code"]

        _context.sdb.update(session_id, user="diana")
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        # 2nd time used
        with pytest.raises(MultipleUsage):
            self.endpoint.parse_request(_token_request)

    def test_do_refresh_access_token(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "offline_access"]
        _cntx = self.endpoint.endpoint_context
        session_id = setup_session(
            _cntx, areq, uid="user", acr=INTERNETPROTOCOLPASSWORD
        )
        _cntx.sdb.update(session_id, user="diana")
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = _cntx.sdb[session_id]["code"]
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _req = self.endpoint.parse_request(_request.to_json())
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "id_token",
        }
        msg = self.endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_do_2nd_refresh_access_token(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "offline_access"]
        _cntx = self.endpoint.endpoint_context
        session_id = setup_session(
            _cntx, areq, uid="user", acr=INTERNETPROTOCOLPASSWORD
        )
        _cntx.sdb.update(session_id, user="diana")
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = _cntx.sdb[session_id]["code"]
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _req = self.endpoint.parse_request(_request.to_json())
        _resp = self.endpoint.process_request(request=_req)

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        _req = self.endpoint.parse_request(_request.to_json())
        _resp = self.endpoint.process_request(request=_req)

        assert set(_resp.keys()) == {"response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "refresh_token",
            "id_token",
        }
        msg = self.endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_do_refresh_access_token_not_allowed(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "offline_access"]
        _cntx = self.endpoint.endpoint_context
        session_id = setup_session(
            _cntx, areq, uid="user", acr=INTERNETPROTOCOLPASSWORD
        )
        _cntx.sdb.update(session_id, user="diana")
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = _cntx.sdb[session_id]["code"]
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        self.endpoint.allow_refresh = False

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _resp["response_args"]["refresh_token"]
        with pytest.raises(ProcessError):
            self.endpoint.parse_request(_request.to_json())
