import os

import pytest
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import init_key_jar
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcendpoint import user_info
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.grant import Grant
from oidcendpoint.id_token import IDToken
from oidcendpoint.oauth2.introspection import Introspection
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.session import Session
from oidcendpoint.oidc.token import Token
from oidcendpoint.session_management import session_key
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
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "claims": {
                "userinfo": {"email": None, "phone_number": None},
                "id_token": {"email": None},
                "introspection": {"email": None, "email_verified": True}
            },
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
                    "class": "oidcendpoint.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "add_claims": True,
                        "add_claim_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "oidcendpoint.jwt_token.JWTToken",
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
        client_id = auth_req['client_id']
        ae = create_authn_event(self.user_id)
        self.session_manager.create_session(ae, auth_req, self.user_id, client_id=client_id,
                                            sub_type=sub_type, sector_identifier=sector_identifier)
        return session_key(self.user_id, client_id)

    def _do_grant(self, auth_req):
        client_id = auth_req['client_id']
        # The user consent module produces a Grant instance
        grant = Grant(scope=auth_req['scope'], resources=[client_id])

        # the grant is assigned to a session (user_id, client_id)
        self.session_manager.set([self.user_id, client_id, grant.id], grant)
        return session_key(self.user_id, client_id, grant.id)

    def _mint_code(self, grant):
        # Constructing an authorization code is now done
        return grant.mint_token(
            'authorization_code',
            value=self.session_manager.token_handler["code"](self.user_id),
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

    def test_parse(self):
        self._create_session(AUTH_REQ)
        session_id = self._do_grant(AUTH_REQ)
        grant = self.session_manager[session_id]
        grant.claims = {
            "introspection": {
                "email": None,
                "email_verified": None,
                "phone_number": None,
                "phone_number_verified": None
            }
        }
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _verifier = JWT(self.endpoint.endpoint_context.keyjar)
        _info = _verifier.unpack(access_token.value)

        assert _info["ttype"] == "T"
        assert _info["phone_number"] == "+46907865000"
        assert set(_info["aud"]) == {"client_1", "https://example.org/appl"}

    def test_info(self):
        self._create_session(AUTH_REQ)
        session_id = self._do_grant(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _info = self.session_manager.token_handler.info(access_token.value)
        assert _info["type"] == "T"
        assert _info["sid"] == session_id

    @pytest.mark.parametrize("enable_claims_per_client", [True, False])
    def test_client_claims(self, enable_claims_per_client):
        self.endpoint.endpoint_context.cdb["client_1"]["introspection_claims"] = {"address": None}

        self.endpoint_context.endpoint[
            "introspection"].kwargs["enable_claims_per_client"] = enable_claims_per_client
        self._create_session(AUTH_REQ)
        session_id = self._do_grant(AUTH_REQ)
        grant = self.session_manager[session_id]
        grant.claims = {
            "introspection": self.endpoint_context.claims_interface.get_claims("client_1",
                                                                               "diana",
                                                                               AUTH_REQ["scope"],
                                                                               usage="introspection")
        }
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _jwt = JWT(key_jar=KEYJAR, iss="client_1")
        res = _jwt.unpack(access_token.value)
        assert enable_claims_per_client is ("address" in res)

    @pytest.mark.parametrize("add_scope", [True, False])
    def test_add_scopes(self, add_scope):
        ec = self.endpoint.endpoint_context
        handler = ec.sdb.handler.handler["access_token"]
        auth_req = dict(AUTH_REQ)
        auth_req["scope"] = ["openid", "profile", "aba"]
        session_id = setup_session(ec, auth_req, uid="diana")
        handler.add_scope = add_scope
        _dic = ec.sdb.upgrade_to_token(key=session_id)

        token = _dic["access_token"]
        _jwt = JWT(key_jar=KEYJAR, iss="client_1")
        res = _jwt.unpack(token)
        assert add_scope is (res.get("scope") == ["openid", "profile"])

    def test_is_expired(self):
        self._create_session(AUTH_REQ)
        session_id = self._do_grant(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        assert access_token.is_active()
        # 4000 seconds in the future. Passed the lifetime.
        assert access_token.is_active(now=time_sans_frac() + 4000) is False
