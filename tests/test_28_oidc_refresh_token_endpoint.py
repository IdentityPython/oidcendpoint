import json
import os

from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.time_util import time_sans_frac
import pytest

from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.client_authn import ClientSecretBasic
from oidcendpoint.client_authn import ClientSecretJWT
from oidcendpoint.client_authn import ClientSecretPost
from oidcendpoint.client_authn import PrivateKeyJWT
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.grant import Grant
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.refresh_token import RefreshAccessToken
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.session_management import db_key
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
        self.session_manager = endpoint_context.session_manager
        self.token_endpoint = endpoint_context.endpoint["token"]
        self.refresh_token_endpoint = endpoint_context.endpoint["refresh_token"]
        self.user_id = "diana"

    def _create_session(self, auth_req, sub_type="public", sector_identifier=''):
        client_id = auth_req['client_id']
        ae = create_authn_event(self.user_id, self.session_manager.salt)
        self.session_manager.create_session(ae, auth_req, self.user_id, client_id=client_id,
                                            sub_type=sub_type,
                                            sector_identifier=sector_identifier)
        return db_key(self.user_id, client_id)

    def _do_grant(self, auth_req):
        client_id = auth_req['client_id']
        # The user consent module produces a Grant instance
        grant = Grant(scope=auth_req['scope'], resources=[client_id])

        # the grant is assigned to a session (user_id, client_id)
        self.session_manager.set([self.user_id, client_id, grant.id], grant)
        return db_key(self.user_id, client_id, grant.id)

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

    def test_init(self):
        assert self.refresh_token_endpoint

    def test_do_refresh_access_token(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "offline_access"]

        self._create_session(areq)
        session_id = self._do_grant(areq)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
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
            "scope",
            "refresh_token"
        }
        msg = self.refresh_token_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_do_refresh_access_token_with_idtoken(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "offline_access"]

        self._create_session(areq)
        session_id = self._do_grant(areq)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.token_endpoint.parse_request(_token_request)
        _resp = self.token_endpoint.process_request(request=_req)

        _refresh_token = _resp["response_args"]["refresh_token"]
        _mngr = self.token_endpoint.endpoint_context.session_manager
        _info = _mngr.get_session_info_by_token(_refresh_token)
        _token = _mngr.find_token(_info["session_id"], _refresh_token)
        _token.usage_rules["supports_minting"].append("id_token")

        _request = REFRESH_TOKEN_REQ.copy()
        _request["refresh_token"] = _refresh_token
        _req = self.refresh_token_endpoint.parse_request(_request.to_json())
        _resp = self.refresh_token_endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            "access_token",
            "token_type",
            "expires_in",
            "scope",
            "refresh_token",
            "id_token"
        }
        msg = self.refresh_token_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_do_2nd_refresh_access_token(self):
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "offline_access"]

        self._create_session(areq)
        session_id = self._do_grant(areq)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
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
            "scope"
        }
        msg = self.refresh_token_endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)
