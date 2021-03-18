import json
import os

import pytest
from cryptojwt.key_jar import build_keyjar
from oidcmsg.oauth2 import TokenExchangeRequest
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest

from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.authz import AuthzHandling
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.id_token import IDToken
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.token import Token
from oidcendpoint.session import session_key
from oidcendpoint.session.grant import ExchangeGrant
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
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
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


USERINFO = UserInfo(json.loads(open(full_path("users.json")).read()))


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "authorization": {
                    "path": "authorization",
                    "class": Authorization,
                    "kwargs": {},
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
                        ],
                        "grant_types_supported": {
                            "authorization_code": True,
                            "urn:ietf:params:oauth:grant-type:token-exchange": True,
                        },
                    },
                },
                "introspection": {
                    "path": "introspection",
                    "class": "oidcendpoint.oauth2.introspection.Introspection",
                    "kwargs": {}
                }
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
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                'supports_minting': ["access_token", "refresh_token", "id_token"],
                                "max_usage": 1
                            },
                            "access_token": {
                                "supports_minting": ["access_token", "refresh_token", "id_token"],
                                "expires_in": 600,
                            },
                            "refresh_token": {
                                'supports_minting': ["access_token", "refresh_token"],
                            }
                        },
                        "expires_in": 43200
                    }
                }
            },
        }
        endpoint_context = EndpointContext(conf)
        endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
            "allowed_scopes": ["openid", "profile"],
        }
        endpoint_context.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.endpoint = endpoint_context.endpoint["token"]
        self.session_manager = endpoint_context.session_manager
        self.user_id = "diana"

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

    def _mint_code(self, grant, client_id):
        session_id = session_key(self.user_id, client_id, grant.id)
        usage_rules = grant.usage_rules.get("authorization_code", {})
        _exp_in = usage_rules.get("expires_in")

        # Constructing an authorization code is now done
        _code = grant.mint_token(
            session_id=session_id,
            endpoint_context=self.endpoint.endpoint_context,
            token_type='authorization_code',
            token_handler=self.session_manager.token_handler["code"],
            usage_rules=usage_rules
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)
            if _exp_in:
                _code.expires_at = utc_time_sans_frac() + _exp_in
        return _code

    def test_token_exchange(self):
        """
        Test that token exchange requests work correctly, removing a scope.
        """
        areq = AUTH_REQ.copy()
        areq["scope"] = ["openid", "profile"]

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            resource=["https://example.com/api"],
            scope=["openid"],
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)

        assert set(_resp.keys()) == {"response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            'access_token', 'token_type', 'scope', 'expires_in', 'issued_token_type'
        }
        assert _resp["response_args"]["scope"] == ["openid"]

    def test_additional_parameters(self):
        """
        Test that a token exchange with additional parameters including
        audience and subject_token_type works.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            resource=["https://example.com/api"],
            requested_token_type="urn:ietf:params:oauth:token-type:access_token",
            audience=["https://example.com/"],
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)

        assert set(_resp.keys()) == {"response_args", "http_headers"}
        assert set(_resp["response_args"].keys()) == {
            'access_token', 'token_type', 'expires_in', 'issued_token_type'
        }
        msg = self.endpoint.do_response(request=_req, **_resp)
        assert isinstance(msg, dict)

    def test_token_exchange_fails_if_disabled(self):
        """
        Test that token exchange fails if it's not included in Token's
        grant_types_supported (that are set in its helper attribute).
        """
        del self.endpoint.helper[
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ]

        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            resource=["https://example.com/api"]
        )

        _resp = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert(
            _resp["error_description"]
            == "Unsupported grant_type: urn:ietf:params:oauth:grant-type:token-exchange"
        )

    def test_wrong_resource(self):
        """
        Test that requesting a token for an unknown resource fails.

        We currently only allow resources that match the issuer's host part.
        TODO: Should we do this?
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            resource=["https://unknown-resource.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_target"
        assert _resp["error_description"] == "Unknown resource"

    def test_wrong_audience(self):
        """
        Test that requesting a token for an unknown audience fails.

        We currently only allow audience that match the issuer.
        TODO: Should we do this?
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            audience=["https://unknown-audience.com/"],
            resource=["https://example.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_target"
        assert _resp["error_description"] == "Unknown audience"

    @pytest.mark.parametrize("missing_attribute", [
        "subject_token_type",
        "subject_token",
    ])
    def test_missing_parameters(self, missing_attribute):
        """
        Test that omitting the subject_token_type fails.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            audience=["https://example.com/"],
            resource=["https://example.com/api"]
        )

        del token_exchange_req[missing_attribute]

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == f"Missing required attribute '{missing_attribute}'"
        )

    @pytest.mark.parametrize("unsupported_type", [
        "unknown",
        "urn:ietf:params:oauth:token-type:refresh_token",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:saml2",
        "urn:ietf:params:oauth:token-type:saml1",
    ])
    def test_unsupported_requested_token_type(self, unsupported_type):
        """
        Test that requesting a token type that is unknown or unsupported fails.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            requested_token_type=unsupported_type,
            audience=["https://example.com/"],
            resource=["https://example.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_target"
        assert (
            _resp["error_description"]
            == "Unsupported requested token type"
        )

    @pytest.mark.parametrize("unsupported_type", [
        "unknown",
        "urn:ietf:params:oauth:token-type:refresh_token",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:saml2",
        "urn:ietf:params:oauth:token-type:saml1",
    ])
    def test_unsupported_subject_token_type(self, unsupported_type):
        """
        Test that providing an unsupported subject token type fails.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type=unsupported_type,
            audience=["https://example.com/"],
            resource=["https://example.com/api"]
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == "Unsupported subject token type"
        )

    def test_unsupported_actor_token(self):
        """
        Test that providing an actor token fails as it's unsupported.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=_token_value,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            actor_token=_resp['response_args']['access_token']
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == "Actor token not supported"
        )

    def test_invalid_token(self):
        """
        Test that providing an invalid token fails.
        """
        areq = AUTH_REQ.copy()

        session_id = self._create_session(areq)
        grant = self.endpoint.endpoint_context.authz(session_id, areq)
        code = self._mint_code(grant, areq['client_id'])

        _cntx = self.endpoint.endpoint_context

        _token_request = TOKEN_REQ_DICT.copy()
        _token_request["code"] = code.value
        _req = self.endpoint.parse_request(_token_request)
        _resp = self.endpoint.process_request(request=_req)

        _token_value = _resp["response_args"]["access_token"]
        _session_info = self.session_manager.get_session_info_by_token(_token_value)
        _token = self.session_manager.find_token(_session_info["session_id"], _token_value)

        token_exchange_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token="invalid_token",
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        )

        _req = self.endpoint.parse_request(
            token_exchange_req.to_json(),
            auth="Basic {}".format("Y2xpZW50XzE6aGVtbGlndA=="),
        )
        _resp = self.endpoint.process_request(request=_req)
        assert set(_resp.keys()) == {"error", "error_description"}
        assert _resp["error"] == "invalid_request"
        assert (
            _resp["error_description"]
            == "Subject token invalid"
        )
