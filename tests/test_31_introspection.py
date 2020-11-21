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
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac
from oidcmsg.time_util import utc_time_sans_frac

from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.exception import UnAuthorizedClient
from oidcendpoint.grant import Grant
from oidcendpoint.oauth2.authorization import Authorization
from oidcendpoint.oauth2.introspection import Introspection
from oidcendpoint.oidc.token import Token
from oidcendpoint.session_management import session_key
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
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
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
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                "jwks_def": {
                    # These keys are used for encrypting the access code, the
                    # refresh token and the access token(when it's not a JWT),
                    # I don't think these should be configurable.
                    # Should these keys be stored somewhere?
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "code"},
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "refresh"},
                        {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "token"},
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
                        "client_authn_method": ["client_secret_post"],
                        "enable_claims_per_client": False,
                    },
                },
                "token": {
                    "path": "token",
                    "class": Token,
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
            conf["token_handler_args"]["token"] = {
                "class": "oidcendpoint.jwt_token.JWTToken",
                "kwargs": {},
            }
        endpoint_context = EndpointContext(conf)
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "introspection_claims": {
                "nickname": None,
                "eduperson_scoped_affiliation": None
            },
        }
        endpoint_context.keyjar.import_jwks_as_json(
            endpoint_context.keyjar.export_jwks_as_json(private=True),
            endpoint_context.issuer,
        )
        self.introspection_endpoint = endpoint_context.endpoint["introspection"]
        self.token_endpoint = endpoint_context.endpoint["token"]
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

    def _create_session(self, auth_req, user_id="", sub_type="public", sector_identifier=''):
        if not user_id:
            user_id = self.user_id
        client_id = auth_req['client_id']
        ae = create_authn_event(self.user_id)
        self.session_manager.create_session(ae, auth_req, user_id, client_id=client_id,
                                            sub_type=sub_type,
                                            sector_identifier=sector_identifier)
        return session_key(self.user_id, client_id)

    def _do_grant(self, auth_req, user_id=''):
        if not user_id:
            user_id = self.user_id
        client_id = auth_req['client_id']
        # The user consent module produces a Grant instance
        grant = Grant(scope=auth_req['scope'], resources=[client_id])

        # the grant is assigned to a session (user_id, client_id)
        self.session_manager.set([user_id, client_id, grant.id], grant)
        return session_key(user_id, client_id, grant.id)

    def _mint_code(self, grant, session_id):
        # Constructing an authorization code is now done
        return grant.mint_token(
            'authorization_code',
            value=self.session_manager.token_handler["code"](session_id),
            expires_at=time_sans_frac() + 300  # 5 minutes from now
        )

    def _mint_access_token(self, grant, session_id, token_ref=None):
        _session_info = self.session_manager.get_session_info(session_id)
        return grant.mint_token(
            'access_token',
            value=self.session_manager.token_handler["access_token"](
                session_id,
                client_id=_session_info["client_id"],
                aud=grant.resources,
                user_claims=None,
                scope=grant.scope,
                sub=_session_info["client_session_info"]['sub']
            ),
            expires_at=time_sans_frac() + 900,  # 15 minutes from now
            based_on=token_ref  # Means the token (tok) was used to mint this token
        )

    def _get_access_token(self, areq):
        self._create_session(areq)
        session_id = self._do_grant(areq)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        return self._mint_access_token(grant, session_id, code)

    def test_parse_no_authn(self):
        access_token = self._get_access_token(AUTH_REQ)
        with pytest.raises(UnAuthorizedClient):
            self.introspection_endpoint.parse_request({"token": access_token.value})

    def test_parse_with_client_auth_in_req(self):
        access_token = self._get_access_token(AUTH_REQ)

        _context = self.introspection_endpoint.endpoint_context
        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )

        assert isinstance(_req, TokenIntrospectionRequest)
        assert set(_req.keys()) == {"token", "client_id", "client_secret"}

    def test_parse_with_wrong_client_authn(self):
        access_token = self._get_access_token(AUTH_REQ)

        _basic_token = "{}:{}".format(
            "client_1",
            self.introspection_endpoint.endpoint_context.cdb["client_1"]["client_secret"]
        )
        _basic_token = as_unicode(base64.b64encode(as_bytes(_basic_token)))
        _basic_authz = "Basic {}".format(_basic_token)

        with pytest.raises(UnAuthorizedClient):
            self.introspection_endpoint.parse_request({"token": access_token.value}, _basic_authz)

    def test_process_request(self):
        access_token = self._get_access_token(AUTH_REQ)

        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": self.introspection_endpoint.endpoint_context.cdb[
                    "client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)

        assert _resp
        assert set(_resp.keys()) == {"response_args"}

    def test_do_response(self):
        access_token = self._get_access_token(AUTH_REQ)

        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": self.introspection_endpoint.endpoint_context.cdb[
                    "client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        msg_info = self.introspection_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg_info, dict)
        assert set(msg_info.keys()) == {"response", "http_headers"}
        assert msg_info["http_headers"] == [
            ("Content-type", "application/json; charset=utf-8"),
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
            "exp",
            "iat"
        }
        assert _payload["active"] is True

    def test_do_response_no_token(self):
        # access_token = self._get_access_token(AUTH_REQ)
        _context = self.introspection_endpoint.endpoint_context
        _req = self.introspection_endpoint.parse_request(
            {
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert "error" in _resp

    def test_access_token(self):
        access_token = self._get_access_token(AUTH_REQ)
        _context = self.introspection_endpoint.endpoint_context
        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        _resp_args = _resp["response_args"]
        assert "sub" in _resp_args
        assert _resp_args["active"]
        assert _resp_args["scope"] == "openid"

    def test_code(self):
        self._create_session(AUTH_REQ)
        session_id = self._do_grant(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)

        _context = self.introspection_endpoint.endpoint_context

        _req = self.introspection_endpoint.parse_request(
            {
                "token": code.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        _resp_args = _resp["response_args"]
        assert _resp_args["active"] is False

    def test_introspection_claims(self):
        self._create_session(AUTH_REQ)
        session_id = self._do_grant(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        self.introspection_endpoint.kwargs["enable_claims_per_client"] = True

        _c_interface = self.introspection_endpoint.endpoint_context.claims_interface
        grant.claims = {
            "introspection": _c_interface.get_claims("client_1",
                                                     self.user_id,
                                                     AUTH_REQ["scope"],
                                                     "introspection")
        }

        _context = self.introspection_endpoint.endpoint_context
        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        _resp_args = _resp["response_args"]
        assert "nickname" in _resp_args
        assert _resp_args["nickname"] == "Dina"
        assert "eduperson_scoped_affiliation" in _resp_args
        assert _resp_args["eduperson_scoped_affiliation"] == ["staff@example.org"]
        assert "family_name" not in _resp_args

    def test_jwt_unknown_key(self):
        _keyjar = build_keyjar(KEYDEFS)

        _jwt = JWT(
            _keyjar,
            iss=self.introspection_endpoint.endpoint_context.issuer,
            lifetime=3600,
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
        access_token = self._get_access_token(AUTH_REQ)
        access_token.expires_at = utc_time_sans_frac() - 1000

        _context = self.introspection_endpoint.endpoint_context

        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert _resp["response_args"]["active"] is False

    def test_revoked_access_token(self):
        access_token = self._get_access_token(AUTH_REQ)
        access_token.revoked = True

        _context = self.introspection_endpoint.endpoint_context

        _req = self.introspection_endpoint.parse_request(
            {
                "token": access_token.value,
                "client_id": "client_1",
                "client_secret": _context.cdb["client_1"]["client_secret"],
            }
        )
        _resp = self.introspection_endpoint.process_request(_req)
        assert _resp["response_args"]["active"] is False
