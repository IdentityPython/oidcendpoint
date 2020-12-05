import json
import os

import pytest
from cryptojwt.key_jar import build_keyjar
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.cookie import CookieDealer
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.session import Session
from oidcendpoint.oidc.token import Token
from oidcendpoint.session import session_key
from oidcendpoint.session.grant import Grant
from oidcendpoint.session.info import ClientSessionInfo
from oidcendpoint.session.info import UserSessionInfo
from oidcendpoint.session.manager import SessionManager
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo

ISS = "https://example.com/"

CLI1 = "https://client1.example.com/"
CLI2 = "https://client2.example.com/"

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)
KEYJAR.import_jwks(KEYJAR.export_jwks(private=True), ISS)

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
    redirect_uri="{}cb".format(ISS),
    scope=["openid"],
    state="STATE",
    response_type="code",
    client_secret="hemligt",
)

AUTH_REQ_DICT = AUTH_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": ISS,
            "password": "mycket hemlig zebra",
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
                    "kwargs": {"client_authn_method": None},
                },
                "registration": {
                    "path": "{}/registration",
                    "class": Registration,
                    "kwargs": {"client_authn_method": None},
                },
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {"client_authn_method": None},
                },
                "token": {"path": "{}/token", "class": Token, "kwargs": {}},
                "userinfo": {
                    "path": "{}/userinfo",
                    "class": userinfo.UserInfo,
                    "kwargs": {"db_file": "users.json"},
                },
                "session": {
                    "path": "{}/end_session",
                    "class": Session,
                    "kwargs": {
                        "post_logout_uri_path": "post_logout",
                        "signing_alg": "ES256",
                        "logout_verify_url": "{}/verify_logout".format(ISS),
                        "client_authn_method": None,
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
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
            "template_dir": "template",
            # 'cookie_name':{
            #     'session': 'oidcop',
            #     'register': 'oidcreg'
            # }
        }
        cookie_conf = {
            "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
            "default_values": {
                "name": "oidcop",
                "domain": "127.0.0.1",
                "path": "/",
                "max_age": 3600,
            },
        }

        self.cd = CookieDealer(**cookie_conf)
        endpoint_context = EndpointContext(conf, cookie_dealer=self.cd, keyjar=KEYJAR)
        endpoint_context.cdb = {
            "client_1": {
                "client_secret": "hemligt",
                "redirect_uris": [("{}cb".format(CLI1), None)],
                "client_salt": "salted",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "token", "code id_token", "id_token"],
                "post_logout_redirect_uris": [("{}logout_cb".format(CLI1), "")],
            },
            "client_2": {
                "client_secret": "hemligare",
                "redirect_uris": [("{}cb".format(CLI2), None)],
                "client_salt": "saltare",
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": ["code", "token", "code id_token", "id_token"],
                "post_logout_redirect_uris": [("{}logout_cb".format(CLI2), "")],
            },
        }
        self.session_manager = endpoint_context.session_manager
        self.authn_endpoint = endpoint_context.endpoint["authorization"]
        self.session_endpoint = endpoint_context.endpoint["session"]
        self.token_endpoint = endpoint_context.endpoint["token"]
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

    def test_to(self):
        self._create_session(AUTH_REQ)
        session_id = self._do_grant(AUTH_REQ)
        grant = self.session_manager[session_id]
        code = self._mint_code(grant, session_id)
        access_token = self._mint_access_token(grant, session_id, code)

        _store = {}
        for k in self.session_manager._db.keys():
            _store[k] = self.session_manager._db[k].to_json()

        assert _store

        _db = {}
        for k, js in _store.items():
            v = json.loads(js)
            if v["type"] == "UserSessionInfo":
                _db[k] = UserSessionInfo().from_json(js)
            elif v["type"] == "ClientSessionInfo":
                _db[k] = ClientSessionInfo().from_json(js)
            elif v["type"] == "grant":
                _db[k] = Grant().from_json(js)

        assert _db

        _mngr = SessionManager(self.session_manager.token_handler, db=_db,
                               conf=self.session_manager.conf)

        _session_info = _mngr.get_session_info_by_token(access_token.value)
        assert _session_info
        code = _mngr.find_token(_session_info["session_id"], code.value)
        assert code.is_active()
