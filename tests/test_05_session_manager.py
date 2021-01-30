import pytest
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.session import MintingNotAllowed
from oidcendpoint.session import session_key
from oidcendpoint.session.grant import Grant
from oidcendpoint.session.info import ClientSessionInfo
from oidcendpoint.session.manager import SessionManager
from oidcendpoint.session.token import AccessToken
from oidcendpoint.session.token import AuthorizationCode
from oidcendpoint.session.token import RefreshToken
from oidcendpoint.token.handler import factory

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)


class DummyEndpointContext():
    def __init__(self):
        self.keyjar = None
        self.issuer = "https://exampel.com"
        self.cdb = {}


class TestSessionManager:
    @pytest.fixture(autouse=True)
    def create_session_manager(self):
        conf = {
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
                        "add_claims": True,
                        "add_claim_by_scope": True,
                        "aud": ["https://example.org/appl"],
                    },
                },
                "refresh": {
                    "class": "oidcendpoint.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": 3600,
                        "aud": ["https://example.org/appl"],
                    }
                }
            }
        }

        token_handler = factory(DummyEndpointContext(), **conf["token_handler_args"])

        self.session_manager = SessionManager(handler=token_handler)
        self.authn_event = AuthnEvent(uid="uid",
                                      valid_until=time_sans_frac() + 1,
                                      authn_info="authn_class_ref")

    @pytest.mark.parametrize("sub_type, sector_identifier", [
        ("pairwise", "https://all.example.com"),
        ("public", ""), ("ephemeral", "")])
    def test_create_session_sub_type(self, sub_type, sector_identifier):
        # First session
        authz_req = AUTH_REQ.copy()
        if sub_type == "pairwise":
            authz_req["sector_identifier_uri"] = sector_identifier

        session_key_1 = self.session_manager.create_session(authn_event=self.authn_event,
                                                            auth_req=authz_req,
                                                            user_id='diana',
                                                            client_id="client_1",
                                                            sub_type=sub_type)

        _user_info_1 = self.session_manager.get_user_session_info(session_key_1)
        assert _user_info_1["subordinate"] == ["client_1"]
        _client_info_1 = self.session_manager.get_client_session_info(session_key_1)
        assert len(_client_info_1["subordinate"]) == 1
        # grant = self.session_manager.get_grant(session_key_1)

        # Second session
        authn_req = AUTH_REQ.copy()
        authn_req["client_id"] = "client_2"
        if sub_type == "pairwise":
            authn_req["sector_identifier_uri"] = sector_identifier

        session_key_2 = self.session_manager.create_session(authn_event=self.authn_event,
                                                            auth_req=authn_req,
                                                            user_id='diana',
                                                            client_id="client_2",
                                                            sub_type=sub_type)

        _user_info_2 = self.session_manager.get_user_session_info(session_key_2)
        assert _user_info_2["subordinate"] == ["client_1", "client_2"]

        grant_1 = self.session_manager.get_grant(session_key_1)
        grant_2 = self.session_manager.get_grant(session_key_2)

        if sub_type in ["pairwise", "public"]:
            assert grant_1.sub == grant_2.sub
        else:
            assert grant_1.sub != grant_2.sub

        # Third session
        authn_req = AUTH_REQ.copy()
        authn_req["client_id"] = "client_3"
        if sub_type == "pairwise":
            authn_req["sector_identifier_uri"] = sector_identifier

        session_key_3 = self.session_manager.create_session(authn_event=self.authn_event,
                                                            auth_req=authn_req,
                                                            user_id='diana',
                                                            client_id="client_3",
                                                            sub_type=sub_type)

        grant_3 = self.session_manager.get_grant(session_key_3)

        if sub_type == "pairwise":
            assert grant_1.sub == grant_2.sub
            assert grant_1.sub == grant_3.sub
            assert grant_3.sub == grant_2.sub
        elif sub_type == "public":
            assert grant_1.sub == grant_2.sub
            assert grant_1.sub == grant_3.sub
            assert grant_3.sub == grant_2.sub
        else:
            assert grant_1.sub != grant_2.sub
            assert grant_1.sub != grant_3.sub
            assert grant_3.sub != grant_2.sub

        # Sub types differ so do authentication request

        assert grant_1.authorization_request != grant_2.authorization_request
        assert grant_1.authorization_request != grant_3.authorization_request
        assert grant_3.authorization_request != grant_2.authorization_request

    def test_grant(self):
        grant = Grant()
        assert grant.issued_token == []
        assert grant.is_active() is True

        code = grant.mint_token('authorization_code', '1234567890')
        assert isinstance(code, AuthorizationCode)
        assert code.is_active()
        assert len(grant.issued_token) == 1
        assert code.max_usage_reached() is False

    def test_code_usage(self):
        grant = Grant()
        assert grant.issued_token == []
        assert grant.is_active() is True

        code = grant.mint_token('authorization_code', value='1234567890')
        assert isinstance(code, AuthorizationCode)
        assert code.is_active()
        assert len(grant.issued_token) == 1

        assert code.usage_rules["supports_minting"] == ['access_token', 'refresh_token']
        access_token = grant.mint_token('access_token', 'give me access', based_on=code)
        assert isinstance(access_token, AccessToken)
        assert access_token.is_active()
        assert len(grant.issued_token) == 2

        refresh_token = grant.mint_token('refresh_token', 'use me to refresh', based_on=code)
        assert isinstance(refresh_token, RefreshToken)
        assert refresh_token.is_active()
        assert len(grant.issued_token) == 3

        code.register_usage()
        assert code.max_usage_reached() is True

        with pytest.raises(MintingNotAllowed):
            grant.mint_token("access_token", 'xxxxxxx', based_on=code)

        grant.revoke_token(based_on=code.value)

        assert access_token.revoked == True
        assert refresh_token.revoked == True

    def test_add_grant(self):
        self.session_manager.create_session(authn_event=self.authn_event,
                                            auth_req=AUTH_REQ,
                                            user_id='diana',
                                            client_id="client_1")

        grant = self.session_manager.add_grant(
            user_id="diana", client_id="client_1",
            scope=["openid", "phoe"],
            claims={"userinfo": {"given_name": None}})

        assert grant.scope == ["openid", "phoe"]

        _grant = self.session_manager.get(['diana', 'client_1', grant.id])

        assert _grant.scope == ["openid", "phoe"]

    def test_find_token(self):
        self.session_manager.create_session(authn_event=self.authn_event,
                                            auth_req=AUTH_REQ,
                                            user_id='diana',
                                            client_id="client_1")

        grant = self.session_manager.add_grant(user_id="diana",
                                               client_id="client_1")

        code = grant.mint_token("authorization_code", value="ABCD")
        access_token = grant.mint_token("access_token", value="007", based_on=code)

        _session_key = session_key('diana', 'client_1', grant.id)
        _token = self.session_manager.find_token(_session_key, access_token.value)

        assert _token.type == "access_token"
        assert _token.id == access_token.id

    def test_get_authentication_event(self):
        session_id = self.session_manager.create_session(authn_event=self.authn_event,
                                                         auth_req=AUTH_REQ,
                                                         user_id='diana',
                                                         client_id="client_1")

        # grant = self.session_manager.add_grant(user_id="diana",
        #                                        client_id="client_1",
        #                                        authn_event=self.authn_event,
        #                                        auth_req=AUTH_REQ)
        #
        # _session_id = session_key('diana', 'client_1', grant.id)
        _info = self.session_manager.get_session_info(session_id, authentication_event=True)
        authn_event = _info["authentication_event"]

        assert isinstance(authn_event, AuthnEvent)
        assert authn_event["uid"] == "uid"
        assert authn_event["authn_info"] == "authn_class_ref"

    def test_get_client_session_info(self):
        self.session_manager.create_session(authn_event=self.authn_event,
                                            auth_req=AUTH_REQ,
                                            user_id='diana',
                                            client_id="client_1")

        grant = self.session_manager.add_grant(user_id="diana",
                                               client_id="client_1")

        _session_id = session_key('diana', 'client_1', grant.id)
        csi = self.session_manager.get_client_session_info(_session_id)

        assert isinstance(csi, ClientSessionInfo)

    def test_get_general_session_info(self):
        _session_id = self.session_manager.create_session(authn_event=self.authn_event,
                                                          auth_req=AUTH_REQ,
                                                          user_id='diana',
                                                          client_id="client_1")

        _session_info = self.session_manager.get_session_info(_session_id)

        assert set(_session_info.keys()) == {'client_id',
                                             'grant_id',
                                             'session_id',
                                             'user_id'}
        assert _session_info["user_id"] == "diana"
        assert _session_info["client_id"] == "client_1"

    def test_get_session_info_by_token(self):
        _session_id = self.session_manager.create_session(authn_event=self.authn_event,
                                            auth_req=AUTH_REQ,
                                            user_id='diana',
                                            client_id="client_1")

        grant = self.session_manager.get_grant(_session_id)
        cval = self.session_manager.token_handler.handler["code"](_session_id)
        code = grant.mint_token("authorization_code", value=cval)
        _session_info = self.session_manager.get_session_info_by_token(code.value)

        assert set(_session_info.keys()) == {'client_id',
                                             'session_id',
                                             'grant_id',
                                             'user_id'}
        assert _session_info["user_id"] == "diana"
        assert _session_info["client_id"] == "client_1"
