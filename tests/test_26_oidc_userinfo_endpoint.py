import json
import os

import pytest
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcendpoint import user_info
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.id_token import IDToken
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import Token
from oidcendpoint.session import session_key
from oidcendpoint.session.grant import Grant
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
    "subject_types_supported": ["public", "pairwise", "ephemeral"],
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
            "id_token": {"class": IDToken, "kwargs": {}},
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
                    "class": Token,
                    "kwargs": {
                        "client_authn_methods": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
                "userinfo": {
                    "path": "userinfo",
                    "class": userinfo.UserInfo,
                    "kwargs": {
                        "claim_types_supported": [
                            "normal",
                            "aggregated",
                            "distributed",
                        ],
                        "client_authn_method": ["bearer_header"],
                    },
                },
            },
            "userinfo": {
                "class": user_info.UserInfo,
                "kwargs": {"db_file": full_path("users.json")},
            },
            # "client_authn": verify_client,
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "oidcendpoint.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "add_on": {
                "custom_scopes": {
                    "function": "oidcendpoint.oidc.add_on.custom_scopes.add_custom_scopes",
                    "kwargs": {
                        "research_and_scholarship": [
                            "name",
                            "given_name",
                            "family_name",
                            "email",
                            "email_verified",
                            "sub",
                            "eduperson_scoped_affiliation",
                        ]
                    },
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
        }
        self.endpoint = endpoint_context.endpoint["userinfo"]
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

    def _mint_code(self, grant):
        # Constructing an authorization code is now done
        return grant.mint_token(
            'authorization_code',
            value=self.session_manager.token_handler["code"](self.user_id),
            expires_at=time_sans_frac() + 300  # 5 minutes from now
        )

    def _mint_access_token(self, grant, session_id, token_ref=None):
        _session_info = self.session_manager.get_session_info(session_id, grant=True)
        return grant.mint_token(
            'access_token',
            value=self.session_manager.token_handler["access_token"](
                session_id,
                client_id=_session_info["client_id"],
                aud=grant.resources,
                user_claims=None,
                scope=grant.scope,
                sub=_session_info["grant"].sub
            ),
            expires_at=time_sans_frac() + 900,  # 15 minutes from now
            based_on=token_ref  # Means the token (tok) was used to mint this token
        )

    def test_init(self):
        assert self.endpoint
        assert set(
            self.endpoint.endpoint_context.provider_info["claims_supported"]
        ) == {
                   "address",
                   "birthdate",
                   "email",
                   "email_verified",
                   "eduperson_scoped_affiliation",
                   "family_name",
                   "gender",
                   "given_name",
                   "locale",
                   "middle_name",
                   "name",
                   "nickname",
                   "phone_number",
                   "phone_number_verified",
                   "picture",
                   "preferred_username",
                   "profile",
                   "sub",
                   "updated_at",
                   "website",
                   "zoneinfo",
               }

    def test_parse(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]

        # Free standing access token, not based on an authorization code
        access_token = self._mint_access_token(grant, session_id)
        _req = self.endpoint.parse_request({}, auth="Bearer {}".format(access_token.value))
        assert set(_req.keys()) == {"client_id", "access_token"}
        assert _req["client_id"] == AUTH_REQ['client_id']
        assert _req["access_token"] == access_token.value

    def test_parse_invalid_token(self):
        _req = self.endpoint.parse_request({}, auth="Bearer invalid")
        assert _req['error'] == "invalid_token"

    def test_process_request(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _req = self.endpoint.parse_request(
            {}, auth="Bearer {}".format(access_token.value)
        )
        args = self.endpoint.process_request(_req)
        assert args

    def test_process_request_not_allowed(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        # 2 things can make the request invalid.
        # 1) The token is not valid anymore or 2) The event is not valid.
        _event = grant.authentication_event
        _event['authn_time'] -= 9000
        _event['valid_until'] -= 9000

        _req = self.endpoint.parse_request(
            {}, auth="Bearer {}".format(access_token.value)
        )
        args = self.endpoint.process_request(_req)
        assert set(args["response_args"].keys()) == {"error", "error_description"}

    # Offline access is presently not checked.
    #
    # def test_process_request_offline_access(self):
    #     auth_req = AUTH_REQ.copy()
    #     auth_req["scope"] = ["openid", "offline_access"]
    #     self._create_session(auth_req)
    #     grant = self._do_grant(auth_req)
    #     code = self._mint_code(grant)
    #     access_token = self._mint_access_token(grant, auth_req['client_id'], code)
    #
    #     _req = self.endpoint.parse_request(
    #         {}, auth="Bearer {}".format(access_token.value)
    #     )
    #     args = self.endpoint.process_request(_req)
    #     assert set(args["response_args"].keys()) =={'response_args', 'client_id'}

    def test_do_response(self):
        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _req = self.endpoint.parse_request(
            {}, auth="Bearer {}".format(access_token.value)
        )
        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        assert res

    def test_do_signed_response(self):
        self.endpoint.endpoint_context.cdb["client_1"]["userinfo_signed_response_alg"] = "ES256"

        session_id = self._create_session(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        _req = self.endpoint.parse_request(
            {}, auth="Bearer {}".format(access_token.value)
        )
        args = self.endpoint.process_request(_req)
        assert args
        res = self.endpoint.do_response(request=_req, **args)
        assert res

    def test_custom_scope(self):
        _auth_req = AUTH_REQ.copy()
        _auth_req["scope"] = ["openid", "research_and_scholarship"]

        session_id =  self._create_session(_auth_req)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant)
        access_token = self._mint_access_token(grant, session_id, code)

        session_info = self.session_manager.get_session_info(session_id)

        self.endpoint.kwargs["add_claims_by_scope"] = True
        self.endpoint.endpoint_context.claims_interface.add_claims_by_scope = True
        grant.claims = {
            "userinfo": self.endpoint.endpoint_context.claims_interface.get_claims(
                session_id=session_id, scopes=_auth_req["scope"], usage="userinfo")
        }

        _req = self.endpoint.parse_request(
            {}, auth="Bearer {}".format(access_token.value)
        )
        args = self.endpoint.process_request(_req)
        assert set(args["response_args"].keys()) == {'eduperson_scoped_affiliation', 'given_name',
                                                     'email_verified', 'email', 'family_name',
                                                     'name', "sub"}
