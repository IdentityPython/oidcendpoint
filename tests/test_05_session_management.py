from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac
import pytest

from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.grant import AccessToken
from oidcendpoint.grant import AuthorizationCode
from oidcendpoint.grant import Grant
from oidcendpoint.grant import MintingNotAllowed
from oidcendpoint.grant import RefreshToken
from oidcendpoint.session_management import SessionManager
from oidcendpoint.token_handler import factory

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
                    }
                }
            }
        }

        token_handler = factory(DummyEndpointContext(), **conf["token_handler_args"])

        self.session_manager = SessionManager({}, handler=token_handler)
        self.authn_event = AuthnEvent(uid="uid",
                                      valid_until=time_sans_frac() + 1,
                                      authn_info="authn_class_ref")

    @pytest.mark.parametrize("sub_type, sector_identifier", [
        ("pairwise", "https://all.example.com"),
        ("public", ""), ("ephemeral", "")])
    def test_create_session_sub_type(self, sub_type, sector_identifier):
        # First session
        self.session_manager.create_session(authn_event=self.authn_event,
                                            auth_req=AUTH_REQ,
                                            user_id='diana',
                                            client_id="client_1",
                                            sub_type=sub_type,
                                            sector_identifier=sector_identifier)

        _user_info = self.session_manager.get(['diana'])
        assert _user_info["subordinate"] == ["client_1"]
        _client_info = self.session_manager.get(['diana', 'client_1'])
        assert _client_info["subordinate"] == []

        # Second session
        authn_req = AUTH_REQ.copy()
        authn_req["client_id"] = "client_2"
        self.session_manager.create_session(authn_event=self.authn_event,
                                            auth_req=authn_req,
                                            user_id='diana',
                                            client_id="client_2",
                                            sub_type=sub_type,
                                            sector_identifier=sector_identifier)

        _user_info = self.session_manager.get(['diana'])
        assert _user_info["subordinate"] == ["client_1", "client_2"]

        _client_info_1 = self.session_manager.get(['diana', 'client_1'])
        _client_info_2 = self.session_manager.get(['diana', 'client_2'])
        if sub_type in ["pairwise", "public"]:
            assert _client_info_1["sub"] == _client_info_2["sub"]
        else:
            assert _client_info_1["sub"] != _client_info_2["sub"]

        # Third session
        authn_req = AUTH_REQ.copy()
        authn_req["client_id"] = "client_3"
        self.session_manager.create_session(authn_event=self.authn_event,
                                            auth_req=authn_req,
                                            user_id='diana',
                                            client_id="client_3",
                                            sub_type=sub_type,
                                            sector_identifier="https://else.example.com")

        _client_info_3 = self.session_manager.get(['diana', 'client_3'])
        if sub_type == "pairwise":
            assert _client_info_1["sub"] == _client_info_2["sub"]
            assert _client_info_1["sub"] != _client_info_3["sub"]
            assert _client_info_3["sub"] != _client_info_2["sub"]
        elif sub_type == "public":
            assert _client_info_1["sub"] == _client_info_2["sub"]
            assert _client_info_1["sub"] == _client_info_3["sub"]
            assert _client_info_3["sub"] == _client_info_2["sub"]
        else:
            assert _client_info_1["sub"] != _client_info_2["sub"]
            assert _client_info_1["sub"] != _client_info_3["sub"]
            assert _client_info_3["sub"] != _client_info_2["sub"]

        # Sub types differ so do authentication request

        assert _client_info_1["authorization_request"] != _client_info_2["authorization_request"]
        assert _client_info_1["authorization_request"] != _client_info_3["authorization_request"]
        assert _client_info_3["authorization_request"] != _client_info_2["authorization_request"]

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

        grant.revoke_all_based_on(code.value)

        assert access_token.revoked == True
        assert refresh_token.revoked == True
