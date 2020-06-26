import json
import os

import pytest
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.scopes import SCOPE2CLAIMS
from oidcendpoint.scopes import STANDARD_CLAIMS
from oidcendpoint.scopes import convert_scopes2claims
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo
from oidcendpoint.userinfo import by_schema
from oidcendpoint.userinfo import claims_match
from oidcendpoint.userinfo import collect_user_info
from oidcendpoint.userinfo import update_claims
from oidcmsg.message import Message
from oidcmsg.oidc import OpenIDRequest
from oidcmsg.oidc import OpenIDSchema

CLAIMS = {
    "userinfo": {
        "given_name": {"essential": True},
        "nickname": None,
        "email": {"essential": True},
        "email_verified": {"essential": True},
        "picture": None,
        "http://example.info/claims/groups": {"value": "red"},
    },
    "id_token": {
        "auth_time": {"essential": True},
        "acr": {"values": ["urn:mace:incommon:iap:silver"]},
    },
}

CLAIMS_2 = {
    "userinfo": {
        "eduperson_scoped_affiliation": {"essential": True},
        "nickname": None,
        "email": {"essential": True},
        "email_verified": {"essential": True},
    }
}

OIDR = OpenIDRequest(
    response_type="code",
    client_id="client1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
    claims=CLAIMS,
)

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

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_DB = json.loads(open(full_path("users.json")).read())


def test_default_scope2claims():
    assert convert_scopes2claims(["openid"], STANDARD_CLAIMS) == {"sub": None}
    assert set(convert_scopes2claims(["profile"], STANDARD_CLAIMS).keys()) == {
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
        "preferred_username",
    }
    assert set(convert_scopes2claims(["email"], STANDARD_CLAIMS).keys()) == {"email",
                                                                             "email_verified"}
    assert set(convert_scopes2claims(["address"], STANDARD_CLAIMS).keys()) == {"address"}
    assert set(convert_scopes2claims(["phone"], STANDARD_CLAIMS).keys()) == {
        "phone_number",
        "phone_number_verified",
    }
    assert convert_scopes2claims(["offline_access"], STANDARD_CLAIMS) == {}

    assert convert_scopes2claims(["openid", "email", "phone"], STANDARD_CLAIMS) == {
        "sub": None,
        "email": None,
        "email_verified": None,
        "phone_number": None,
        "phone_number_verified": None,
    }


def test_custom_scopes():
    custom_scopes = {
        "research_and_scholarship": [
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "sub",
            "iss",
            "eduperson_scoped_affiliation",
        ]
    }

    _scopes = SCOPE2CLAIMS.copy()
    _scopes.update(custom_scopes)
    _available_claims = STANDARD_CLAIMS[:]
    _available_claims.append('eduperson_scoped_affiliation')

    assert set(convert_scopes2claims(["email"], _available_claims, map=_scopes).keys()) == {
        "email",
        "email_verified",
    }
    assert set(convert_scopes2claims(["address"], _available_claims, map=_scopes).keys()) == {
        "address"}
    assert set(convert_scopes2claims(["phone"], _available_claims, map=_scopes).keys()) == {
        "phone_number",
        "phone_number_verified",
    }

    assert set(convert_scopes2claims(["research_and_scholarship"], _available_claims,
                                     map=_scopes).keys()) == {
               "name",
               "given_name",
               "family_name",
               "email",
               "email_verified",
               "sub",
               "eduperson_scoped_affiliation",
           }


PROVIDER_INFO = {
    "claims_supported": ["auth_time", "acr", "given_name",
                         "nickname",
                         "email",
                         "email_verified",
                         "picture",
                         "http://example.info/claims/groups",
                         ]
}


def test_update_claims_authn_req_id_token():
    _session_info = {"authn_req": OIDR}
    claims = update_claims(_session_info, "id_token", PROVIDER_INFO)
    assert set(claims.keys()) == {"auth_time", "acr"}


def test_update_claims_authn_req_userinfo():
    _session_info = {"authn_req": OIDR}
    claims = update_claims(_session_info, "userinfo", PROVIDER_INFO)
    assert set(claims.keys()) == {
        "given_name",
        "nickname",
        "email",
        "email_verified",
        "picture",
        "http://example.info/claims/groups",
    }


def test_update_claims_authzreq_id_token():
    _session_info = {"authn_req": OIDR}
    claims = update_claims(_session_info, "id_token", PROVIDER_INFO)
    assert set(claims.keys()) == {"auth_time", "acr"}


def test_update_claims_authzreq_userinfo():
    _session_info = {"authn_req": OIDR}
    claims = update_claims(_session_info, "userinfo", PROVIDER_INFO)
    assert set(claims.keys()) == {
        "given_name",
        "nickname",
        "email",
        "email_verified",
        "picture",
        "http://example.info/claims/groups",
    }


def test_clams_value():
    assert claims_match("red", CLAIMS["userinfo"]["http://example.info/claims/groups"])


def test_clams_values():
    assert claims_match("urn:mace:incommon:iap:silver", CLAIMS["id_token"]["acr"])


def test_clams_essential():
    assert claims_match(["foobar@example"], CLAIMS["userinfo"]["email"])


def test_clams_none():
    assert claims_match(["angle"], CLAIMS["userinfo"]["nickname"])


def test_by_schema():
    # There are no requested or optional claims defined for Message
    assert by_schema(Message, sub="John") == {}

    assert by_schema(OpenIDSchema, sub="John", given_name="John", age=34) == {
        "sub": "John",
        "given_name": "John",
    }


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class TestCollectUserInfo:
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        self.endpoint_context = EndpointContext(
            {
                "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_DB}},
                "password": "we didn't start the fire",
                "issuer": "https://example.com/op",
                "token_expires_in": 900,
                "grant_expires_in": 600,
                "refresh_token_expires_in": 86400,
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
                        "kwargs": {
                            "response_types_supported": [
                                " ".join(x) for x in RESPONSE_TYPES_SUPPORTED
                            ],
                            "response_modes_supported": ["query", "fragment", "form_post"],
                            "claims_parameter_supported": True,
                            "request_parameter_supported": True,
                            "request_uri_parameter_supported": True,
                        },
                    },
                },
                "keys": {
                    "public_path": "jwks.json",
                    "key_defs": KEYDEFS,
                    "uri_path": "static/jwks.json",
                },
                "authentication": {
                    "anon": {
                        "acr": INTERNETPROTOCOLPASSWORD,
                        "class": "oidcendpoint.user_authn.user.NoAuthn",
                        "kwargs": {"user": "diana"},
                    }
                },
                "template_dir": "template",
            }
        )
        # Just has to be there
        self.endpoint_context.cdb['client1'] = {}

    def test_collect_user_info(self):
        _req = OIDR.copy()
        _req["claims"] = CLAIMS_2

        _session_info = {"authn_req": _req}
        session = _session_info.copy()
        session["sub"] = "doe"
        session["uid"] = "diana"
        session["authn_event"] = create_authn_event("diana", "salt")

        res = collect_user_info(self.endpoint_context, session)

        assert res == {
            "nickname": "Dina",
            "sub": "doe",
            "email": "diana@example.org",
            "email_verified": False,
        }

    def test_collect_user_info_2(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email"
        del _req["claims"]

        _session_info = {"authn_req": _req}
        session = _session_info.copy()
        session["sub"] = "doe"
        session["uid"] = "diana"
        session["authn_event"] = create_authn_event("diana", "salt")

        self.endpoint_context.provider_info["scopes_supported"] = [
            "openid", "email", "offline_access"
        ]
        res = collect_user_info(self.endpoint_context, session)

        assert res == {
            "sub": "doe",
            "email": "diana@example.org",
            "email_verified": False,
        }

    def test_collect_user_info_scope_not_supported(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email address"
        del _req["claims"]

        _session_info = {"authn_req": _req}
        session = _session_info.copy()
        session["sub"] = "doe"
        session["uid"] = "diana"
        session["authn_event"] = create_authn_event("diana", "salt")

        # Scope address not supported
        self.endpoint_context.provider_info["scopes_supported"] = [
            "openid", "email", "offline_access"
        ]
        res = collect_user_info(self.endpoint_context, session)

        assert res == {
            "sub": "doe",
            "email": "diana@example.org",
            "email_verified": False,
        }


class TestCollectUserInfoCustomScopes:
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        self.endpoint_context = EndpointContext(
            {
                "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_DB}},
                "password": "we didn't start the fire",
                "issuer": "https://example.com/op",
                "token_expires_in": 900,
                "grant_expires_in": 600,
                "refresh_token_expires_in": 86400,
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
                        "kwargs": {
                            "response_types_supported": [
                                " ".join(x) for x in RESPONSE_TYPES_SUPPORTED
                            ],
                            "response_modes_supported": ["query", "fragment", "form_post"],
                            "claims_parameter_supported": True,
                            "request_parameter_supported": True,
                            "request_uri_parameter_supported": True,
                        },
                    },
                },
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
                                "iss",
                                "eduperson_scoped_affiliation",
                            ]
                        },
                    }
                },
                "keys": {
                    "public_path": "jwks.json",
                    "key_defs": KEYDEFS,
                    "uri_path": "static/jwks.json",
                },
                "authentication": {
                    "anon": {
                        "acr": INTERNETPROTOCOLPASSWORD,
                        "class": "oidcendpoint.user_authn.user.NoAuthn",
                        "kwargs": {"user": "diana"},
                    }
                },
                "template_dir": "template",
            }
        )
        self.endpoint_context.cdb['client1'] = {}

    def test_collect_user_info(self):
        _session_info = {"authn_req": OIDR}
        session = _session_info.copy()
        session["sub"] = "doe"
        session["uid"] = "diana"
        session["authn_event"] = create_authn_event("diana", "salt")

        res = collect_user_info(self.endpoint_context, session)

        assert res == {
            'email': 'diana@example.org',
            'email_verified': False,
            'nickname': 'Dina',
            'given_name': 'Diana',
            'sub': 'doe'
        }

    def test_collect_user_info_2(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email"
        del _req["claims"]

        _session_info = {"authn_req": _req}
        session = _session_info.copy()
        session["sub"] = "doe"
        session["uid"] = "diana"
        session["authn_event"] = create_authn_event("diana", "salt")

        self.endpoint_context.provider_info["claims_supported"].remove("email")
        self.endpoint_context.provider_info["claims_supported"].remove("email_verified")

        res = collect_user_info(self.endpoint_context, session)

        assert res == {"sub": "doe"}

    def test_collect_user_info_scope_not_supported(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email address"
        del _req["claims"]

        _session_info = {"authn_req": _req}
        session = _session_info.copy()
        session["sub"] = "doe"
        session["uid"] = "diana"
        session["authn_event"] = create_authn_event("diana", "salt")

        # Scope address not supported
        self.endpoint_context.provider_info["scopes_supported"] = [
            "openid", "email", "offline_access"
        ]
        res = collect_user_info(self.endpoint_context, session)

        assert res == {
            "sub": "doe",
            "email": "diana@example.org",
            "email_verified": False,
        }
