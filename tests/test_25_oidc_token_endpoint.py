import json
import os

from cryptojwt import JWT
from cryptojwt.key_jar import build_keyjar
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.time_util import time_sans_frac
import pytest

from oidcendpoint import JWT_BEARER
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.exception import UnAuthorizedClient
from oidcendpoint.grant import Grant
from oidcendpoint.id_token import IDToken
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
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
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
                    "class": AccessToken,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_basic",
                            "client_secret_post",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
                "refresh_token": {
                    "path": "token",
                    "class": RefreshAccessToken,
                    "kwargs": {},
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
            "id_token": {"class": IDToken, "kwargs": {}},
        }
        endpoint_context = EndpointContext(conf)
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }
        endpoint_context.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.endpoint = endpoint_context.endpoint["token"]
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

    def _create_session(self, auth_req, sub_type="public", sector_identifier=''):
        client_id = auth_req['client_id']
        ae = create_authn_event(self.user_id, self.session_manager.salt)
        self.session_manager.create_session(ae, auth_req, self.user_id, client_id=client_id,
                                            sub_type=sub_type, sector_identifier=sector_identifier)
        return db_key(self.user_id, client_id)

    def _do_grant(self, auth_req):
        client_id = auth_req['client_id']
        # The user consent module produces a Grant instance
        grant = Grant(scope=auth_req['scope'], resources=[client_id])

        # the grant is assigned to a session (user_id, client_id)
        self.session_manager.set([self.user_id, client_id, grant.id], grant)
        return grant

    def _mint_code(self, grant, client_id):
        sid = db_key(self.user_id, client_id)
        # Constructing an authorization code is now done
        return grant.mint_token(
            'authorization_code',
            value=self.session_manager.token_handler["code"](sid),
            expires_at=time_sans_frac() + 300  # 5 minutes from now
        )

    def _mint_access_token(self, grant, client_id, token_ref=None):
        _csi = self.session_manager.get([self.user_id, client_id])
        return grant.mint_token(
            'access_token',
            value=self.session_manager.token_handler["access_token"](
                db_key(self.user_id, client_id),
                client_id=client_id,
                aud=grant.resources,
                user_claims=None,
                scope=grant.scope,
                sub=_csi['sub']
            ),
            expires_at=time_sans_frac() + 900,  # 15 minutes from now
            based_on=token_ref  # Means the token (tok) was used to mint this token
        )

    def test_init(self):
        assert self.endpoint

    def test_signing_alg_values(self):
        """
        According to
        https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        The value "none" MUST NOT be used for the
        token_endpoint_auth_signing_alg_values_supported field.
        """
        assert "none" not in self.endpoint.endpoint_info[
            "token_endpoint_auth_signing_alg_values_supported"
        ]

    def test_parse(self):
        self._create_session(AUTH_REQ)
        grant = self._do_grant(AUTH_REQ)
        code = self._mint_code(grant, AUTH_REQ['client_id'])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)

        assert isinstance(_req, AccessTokenRequest)
        assert set(_req.keys()) == set(_token_request.keys())

    def test_process_request(self):
        self._create_session(AUTH_REQ)
        grant = self._do_grant(AUTH_REQ)
        code = self._mint_code(grant, AUTH_REQ['client_id'])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value

        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        assert _resp
        assert set(_resp.keys()) == {"http_headers", "response_args"}

    def test_process_request_using_code_twice(self):
        self._create_session(AUTH_REQ)
        grant = self._do_grant(AUTH_REQ)
        code = self._mint_code(grant, AUTH_REQ['client_id'])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value

        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        # 2nd time used
        # TODO: There is a bug in _post_parse_request, the returned error
        # should be invalid_grant, not invalid_client
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        assert _resp
        assert set(_resp.keys()) == {"error"}

    def test_do_response(self):
        self._create_session(AUTH_REQ)
        grant = self._do_grant(AUTH_REQ)
        code = self._mint_code(grant, AUTH_REQ['client_id'])

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)

        _resp = self.endpoint.process_request(request=_req)
        msg = self.endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_process_request_using_private_key_jwt(self):
        self._create_session(AUTH_REQ)
        grant = self._do_grant(AUTH_REQ)
        code = self._mint_code(grant, AUTH_REQ['client_id'])

        _token_request = TOKEN_REQ_DICT.copy()
        del _token_request["client_id"]
        del _token_request["client_secret"]
        _context = self.endpoint.endpoint_context

        _jwt = JWT(CLIENT_KEYJAR, iss=AUTH_REQ["client_id"], sign_alg="RS256")
        _jwt.with_jti = True
        _assertion = _jwt.pack({"aud": [_context.endpoint["token"].full_path]})
        _token_request.update(
            {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}
        )
        _token_request["code"] = code.value

        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        # 2nd time used
        with pytest.raises(UnAuthorizedClient):
            self.endpoint.parse_request(_token_request)
