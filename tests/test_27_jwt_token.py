import os

import pytest
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import init_key_jar
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcendpoint import user_info
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.authz import AuthzHandling
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.id_token import IDToken
from oidcendpoint.oauth2.introspection import Introspection
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.session import Session
from oidcendpoint.oidc.token import Token
from oidcendpoint.session import session_key
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

ISSUER = "https://example.com/"

KEYJAR = init_key_jar(key_defs=KEYDEFS, issuer_id=ISSUER)
KEYJAR.import_jwks(KEYJAR.export_jwks(True, ISSUER), "")

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

TOKEN_REQ_DICT = TOKEN_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISSUER,
            "password": "mycket hemligt",
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "token_handler_args": {
                "jwks_def": {
                    "private_path": "private/token_jwks.json",
                    "read_only": False,
                    "key_defs": [
                        {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}
                    ],
                },
                "code": {"lifetime": 600},
                "token": {
                    "class": "oidcendpoint.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "base_claims": {"eduperson_scoped_affiliation": None},
                        "add_claims_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "oidcendpoint.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "aud": ["https://example.org/appl"],
                    },
                },
            },
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
                "token": {"path": "{}/token", "class": Token, "kwargs": {}},
                "session": {"path": "{}/end_session", "class": Session},
                "introspection": {
                    "path": "{}/introspection",
                    "class": Introspection
                }
            },
            "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcendpoint.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
            },
            "id_token": {"class": IDToken},
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                'supports_minting': ["access_token", "refresh_token", "id_token"],
                                "max_usage": 1
                            },
                            "access_token": {},
                            "refresh_token": {
                                'supports_minting': ["access_token", "refresh_token"],
                            }
                        },
                        "expires_in": 43200
                    }
                }
            },
        }

        self.endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        self.session_manager = self.endpoint_context.session_manager
        self.user_id = "diana"
        self.endpoint = self.endpoint_context.endpoint["session"]

    def _create_session(self, auth_req, sub_type="public", sector_identifier=''):
        if sector_identifier:
            authz_req = auth_req.copy()
            authz_req["sector_identifier_uri"] = sector_identifier
        else:
            authz_req = auth_req
        client_id = authz_req['client_id']
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(ae, authz_req, self.user_id,
                                                   client_id=client_id,
                                                   sub_type=sub_type)

    def _mint_code(self, grant):
        # Constructing an authorization code is now done
        return grant.mint_token(
            'authorization_code',
            value=self.session_manager.token_handler["code"](self.user_id),
            expires_in=300  # 5 minutes from now
        )

    def _mint_access_token(self, grant, session_id, token_ref=None):
        _session_info = self.session_manager.get_session_info(session_id)
        at_handler = self.session_manager.token_handler["access_token"]
        return grant.mint_token(
            'access_token',
            value=at_handler(session_id),
            expires_in=at_handler.lifetime,
            based_on=token_ref  # Means the token (tok) was used to mint this token
        )

    def _mint_refresh_token(self, grant, session_id, token_ref=None):
        _session_info = self.session_manager.get_session_info(session_id)
        rt_handler = self.session_manager.token_handler["refresh_token"]
        return grant.mint_token(
            'refresh_token',
            value=rt_handler(session_id),
            expires_in=rt_handler.lifetime,
            based_on=token_ref  # Means the token (tok) was used to mint this token
        )

    def test_parse(self):
        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.endpoint_context.authz(session_id=session_id, request=AUTH_REQ)
        # grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _verifier = JWT(self.endpoint.endpoint_context.keyjar)
        _info = _verifier.unpack(access_token.value)

        assert _info["ttype"] == "T"
        assert _info["eduperson_scoped_affiliation"] == ["staff@example.org"]
        assert set(_info["aud"]) == {"client_1"}

    def test_info(self):
        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.endpoint_context.authz(session_id=session_id, request=AUTH_REQ)
        #
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _info = self.session_manager.token_handler.info(access_token.value)
        assert _info["type"] == "T"
        assert _info["sid"] == session_id

    @pytest.mark.parametrize("enable_claims_per_client", [True, False])
    def test_enable_claims_per_client(self, enable_claims_per_client):
        # Set up configuration
        self.endpoint.endpoint_context.cdb["client_1"]["token_claims"] = {"address": None}
        self.endpoint_context.session_manager.token_handler.handler["access_token"].kwargs[
            "enable_claims_per_client"] = enable_claims_per_client

        session_id = self._create_session(AUTH_REQ)
        # apply consent
        grant = self.endpoint_context.authz(session_id=session_id, request=AUTH_REQ)
        #
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _jwt = JWT(key_jar=KEYJAR, iss="client_1")
        res = _jwt.unpack(access_token.value)
        assert enable_claims_per_client is ("address" in res)

    def test_is_expired(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        assert access_token.is_active()
        # 4000 seconds in the future. Passed the lifetime.
        assert access_token.is_active(now=time_sans_frac() + 4000) is False
