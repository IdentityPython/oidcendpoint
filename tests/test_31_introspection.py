import base64
import json
import os

import pytest
from cryptojwt import JWT
from cryptojwt import as_unicode
from cryptojwt.key_jar import build_keyjar
from cryptojwt.utils import as_bytes
from oidcmsg.oauth2 import TokenIntrospectionRequest
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import utc_time_sans_frac

from oidcendpoint.client_authn import ClientSecretPost
from oidcendpoint.client_authn import UnknownOrNoAuthnMethod
from oidcendpoint.client_authn import WrongAuthnMethod
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.oauth2.authorization import Authorization
from oidcendpoint.oauth2.introspection import Introspection
from oidcendpoint.oidc.token_coop import TokenCoop
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
    response_type="code id_token",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


@pytest.mark.parametrize("jwt_token", [True, False])
class TestEndpoint:
    @pytest.fixture(autouse=True)
    def create_endpoint(self, jwt_token):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "jwks": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                "jwks_def": {
                    # These keys are used for encrypting the access code, the
                    # refresh token and the access token(when it's not a JWT),
                    # I don't think these should be configurable.
                    # Should these keys be stored somewhere?
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": 24, "use": ["enc"],
                         "kid": "code"},
                        {"type": "oct", "bytes": 24, "use": ["enc"],
                         "kid": "refresh"},
                        {"type": "oct", "bytes": 24, "use": ["enc"],
                         "kid": "token"},
                    ],
                },
                "code": {"lifetime": 600},
                "token": {"lifetime": 3600},
                "refresh": {"lifetime": 86400},
            },
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "introspection": {
                    "path": "{}/intro",
                    "class": Introspection,
                    "kwargs": {
                        "release": ["username"],
                        "client_authn_method": {"client_secret_post": ClientSecretPost},
                    },
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
            },
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcendpoint.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "userinfo": {
                "path": "{}/userinfo",
                "class": UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
            },
            "client_authn": verify_client,
            "template_dir": "template",
        }
        if jwt_token:
            conf["token_handler_args"]["token"]["class"] = \
                "oidcendpoint.jwt_token.JWTToken"
        endpoint_context = EndpointContext(conf)
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        endpoint_context.keyjar.import_jwks_as_json(
            endpoint_context.keyjar.export_jwks_as_json(private=True),
            endpoint_context.issuer,
        )
        self.introspection_endpoint = endpoint_context.endpoint["introspection"]
        self.token_endpoint = endpoint_context.endpoint["token"]

    def _create_at(self, uid, lifetime=0, with_jti=False):
        _context = self.introspection_endpoint.endpoint_context

        session_id = setup_session(
            _context,
            AUTH_REQ,
            uid=uid,
            acr=INTERNETPROTOCOLPASSWORD,
        )
        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = _context.sdb[session_id]["code"]
        _context.sdb.update(session_id, user=uid)

        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)
        _resp = AccessTokenResponse(**_resp["response_args"])
        return _resp["access_token"]

    def test_parse_no_authn(self):
        _token = self._create_at("diana")
        with pytest.raises(UnknownOrNoAuthnMethod):
            self.introspection_endpoint.parse_request({"token": _token})

    def test_parse_with_client_auth_in_req(self):
        _context = self.introspection_endpoint.endpoint_context
        _token = self._create_at("diana")
        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )

        assert isinstance(_req, TokenIntrospectionRequest)
        assert set(_req.keys()) == {"token", "client_id", "client_secret"}

    def test_parse_with_wrong_client_authn(self):
        _context = self.introspection_endpoint.endpoint_context
        _token = self._create_at("diana")
        _basic_token = "{}:{}".format(
            "client_1", _context.cdb["client_1"]["client_secret"]
        )
        _basic_token = as_unicode(base64.b64encode(as_bytes(_basic_token)))
        _basic_authz = "Basic {}".format(_basic_token)

        with pytest.raises(WrongAuthnMethod):
            self.introspection_endpoint.parse_request({"token": _token}, _basic_authz)

    def test_process_request(self):
        _context = self.introspection_endpoint.endpoint_context
        _token = self._create_at("diana", lifetime=6000)
        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)

        assert _resp
        assert set(_resp.keys()) == {"response_args"}

    def test_do_response(self):
        _context = self.introspection_endpoint.endpoint_context
        _token = self._create_at("diana", lifetime=6000, with_jti=True)
        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        msg_info = self.introspection_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg_info, dict)
        assert set(msg_info.keys()) == {"response", "http_headers"}
        assert msg_info["http_headers"] == [
            ("Content-type", "application/json"),
            ("Pragma", "no-cache"),
            ("Cache-Control", "no-store"),
        ]
        _payload = json.loads(msg_info["response"])
        assert set(_payload.keys()) == {
            "active",
            "iss",
            "scope",
            "token_type",
            "sub",
            "client_id",
        }
        assert _payload["active"] is True

    def test_do_response_no_token(self):
        _context = self.introspection_endpoint.endpoint_context
        self._create_at("diana", lifetime=6000, with_jti=True)
        _req = self.introspection_endpoint.parse_request(
            {
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert "error" in _resp

    def test_access_token(self):
        _context = self.introspection_endpoint.endpoint_context
        _token = self._create_at("diana", lifetime=6000, with_jti=True)
        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        _resp_args = _resp["response_args"]
        assert "sub" in _resp_args
        assert _resp_args["active"]
        assert _resp_args["scope"] == "openid"

    def test_jwt_unknown_key(self):
        _keyjar = build_keyjar(KEYDEFS)

        _jwt = JWT(
            _keyjar,
            iss=self.introspection_endpoint.endpoint_context.issuer,
            lifetime=3600
        )

        _jwt.with_jti = True

        _payload = {"sub": "subject_id"}
        _token = _jwt.pack(_payload, aud="client_1")
        _context = self.introspection_endpoint.endpoint_context

        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )

        _req = self.introspection_endpoint.parse_request(_req)
        _resp = self.introspection_endpoint.process_request(_req)
        assert _resp["response_args"]["active"] is False

    def test_expired_access_token(self):
        _context = self.introspection_endpoint.endpoint_context
        _token = self._create_at("diana", lifetime=6000, with_jti=True)
        _info = self.token_endpoint.endpoint_context.sdb[_token]
        _info['expires_at'] = utc_time_sans_frac() - 1000
        self.token_endpoint.endpoint_context.sdb[_token] = _info

        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert _resp["response_args"]["active"] is False

    def test_revoked_access_token(self):
        _token = self._create_at("diana", lifetime=6000, with_jti=True)
        _context = self.introspection_endpoint.endpoint_context

        self.token_endpoint.endpoint_context.sdb.revoke_session(
            token=_token)

        _req = self.introspection_endpoint.parse_request(
            {
                "token": _token,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert _resp["response_args"]["active"] is False
