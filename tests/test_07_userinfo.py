import json
import os

from oidcmsg.oidc import OpenIDRequest
import pytest

from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.grant import Grant
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.scopes import SCOPE2CLAIMS
from oidcendpoint.scopes import STANDARD_CLAIMS
from oidcendpoint.scopes import convert_scopes2claims
from oidcendpoint.session_management import db_key
from oidcendpoint.session_management import unpack_db_key
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo
from oidcendpoint.userinfo import ClaimsInterface

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
    assert set(convert_scopes2claims(["email"], STANDARD_CLAIMS).keys()) == {
        "email",
        "email_verified",
    }
    assert set(convert_scopes2claims(["address"], STANDARD_CLAIMS).keys()) == {
        "address"
    }
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
    _available_claims.append("eduperson_scoped_affiliation")

    assert set(
        convert_scopes2claims(["email"], _available_claims, map=_scopes).keys()
    ) == {"email", "email_verified", }
    assert set(
        convert_scopes2claims(["address"], _available_claims, map=_scopes).keys()
    ) == {"address"}
    assert set(
        convert_scopes2claims(["phone"], _available_claims, map=_scopes).keys()
    ) == {"phone_number", "phone_number_verified", }

    assert set(
        convert_scopes2claims(
            ["research_and_scholarship"], _available_claims, map=_scopes
        ).keys()
    ) == {
               "name",
               "given_name",
               "family_name",
               "email",
               "email_verified",
               "sub",
               "eduperson_scoped_affiliation",
           }


PROVIDER_INFO = {
    "claims_supported": [
        "auth_time",
        "acr",
        "given_name",
        "nickname",
        "email",
        "email_verified",
        "picture",
        "http://example.info/claims/groups",
    ]
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
                            "response_modes_supported": [
                                "query",
                                "fragment",
                                "form_post",
                            ],
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
        self.endpoint_context.cdb["client1"] = {}
        self.session_manager = self.endpoint_context.session_manager
        self.claims_interface = ClaimsInterface(self.endpoint_context, "userinfo")
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
        return db_key(self.user_id, client_id, grant.id)

    def test_collect_user_info(self):
        _req = OIDR.copy()
        _req["claims"] = CLAIMS_2

        self._create_session(_req)
        session_id = self._do_grant(_req)
        _uid, _cid, _gid = unpack_db_key(session_id)

        _restriction = self.claims_interface.get_claims(client_id=_cid, user_id=_uid,
                                                        scopes=OIDR["scope"])

        res = self.claims_interface.get_user_claims("diana", _restriction)

        assert res == {
            'eduperson_scoped_affiliation': ['staff@example.org'],
            "nickname": "Dina",
            "email": "diana@example.org",
            "email_verified": False,
        }

    def test_collect_user_info_2(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email"
        del _req["claims"]

        self._create_session(_req)
        session_id = self._do_grant(_req)
        _uid, _cid, _gid = unpack_db_key(session_id)

        self.claims_interface.add_claims_by_scope = True
        _restriction = self.claims_interface.get_claims(client_id=_cid, user_id=_uid,
                                                        scopes=_req["scope"])

        res = self.claims_interface.get_user_claims("diana", _restriction)

        assert res == {
            "email": "diana@example.org",
            "email_verified": False,
        }

    def test_collect_user_info_scope_not_supported(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email address"
        del _req["claims"]

        self._create_session(_req)
        session_id = self._do_grant(_req)
        _uid, _cid, _gid = unpack_db_key(session_id)

        self.claims_interface.add_claims_by_scope = False
        _restriction = self.claims_interface.get_claims(client_id=_cid, user_id=_uid,
                                                        scopes=_req["scope"])

        res = self.claims_interface.get_user_claims("diana", _restriction)

        assert res == {}


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
                            "response_modes_supported": [
                                "query",
                                "fragment",
                                "form_post",
                            ],
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
        self.endpoint_context.cdb["client1"] = {}
        self.endpoint_context.cdb["client1"] = {}
        self.session_manager = self.endpoint_context.session_manager
        self.claims_interface = ClaimsInterface(self.endpoint_context, "userinfo")
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
        return db_key(self.user_id, client_id, grant.id)

    def test_collect_user_info(self):
        self._create_session(OIDR)
        session_id = self._do_grant(OIDR)
        _uid, _cid, _gid = unpack_db_key(session_id)

        self.claims_interface.add_claims_by_scope = False
        _restriction = self.claims_interface.get_claims(client_id=_cid, user_id=_uid,
                                                        scopes=OIDR["scope"])

        res = self.claims_interface.get_user_claims("diana", _restriction)

        assert res == {
            "email": "diana@example.org",
            "email_verified": False,
            "nickname": "Dina",
            "given_name": "Diana",
        }

    def test_collect_user_info_2(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email"
        del _req["claims"]

        self._create_session(_req)
        session_id = self._do_grant(_req)
        _uid, _cid, _gid = unpack_db_key(session_id)

        self.claims_interface.add_claims_by_scope = True
        _restriction = self.claims_interface.get_claims(client_id=_cid, user_id=_uid,
                                                        scopes=_req["scope"])

        res = self.claims_interface.get_user_claims("diana", _restriction)

        assert res == {'email': 'diana@example.org', 'email_verified': False}

    def test_collect_user_info_scope_not_supported(self):
        _req = OIDR.copy()
        _req["scope"] = "openid email address"
        del _req["claims"]

        self._create_session(_req)
        session_id = self._do_grant(_req)
        _uid, _cid, _gid = unpack_db_key(session_id)

        # Address asked for but not supported
        self.endpoint_context.provider_info["scopes_supported"] = [
            "openid",
            "email",
            "offline_access",
        ]

        self.claims_interface.add_claims_by_scope = True
        _restriction = self.claims_interface.get_claims(client_id=_cid, user_id=_uid,
                                                        scopes=_req["scope"])

        res = self.claims_interface.get_user_claims("diana", _restriction)

        assert res == {
            'email': 'diana@example.org',
            'email_verified': False
        }
