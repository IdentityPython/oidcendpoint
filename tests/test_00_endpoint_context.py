import io
from copy import copy

import pytest
import yaml
from cryptojwt.key_jar import build_keyjar

from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.exception import ConfigurationError
from oidcendpoint.id_token import IDToken
from oidcendpoint.oidc.add_on.pkce import add_pkce_support
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.session import Session
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc.userinfo import UserInfo
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

KEYJAR = build_keyjar(KEYDEFS)

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "capabilities": {},
    "jwks": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS, "read_only": True},
    "id_token": {
        "class": IDToken,
        "kwargs": {}
    },
    "endpoint": {
        "provider_config": {
            "path": ".well-known/openid-configuration",
            "class": ProviderConfiguration,
            "kwargs": {},
        },
        "registration_endpoint": {
            "path": "registration",
            "class": Registration,
            "kwargs": {},
        },
        "authorization_endpoint": {
            "path": "authorization",
            "class": Authorization,
            "kwargs": {},
        },
        "token_endpoint": {"path": "token", "class": AccessToken, "kwargs": {}},
        "userinfo_endpoint": {
            "path": "userinfo",
            "class": UserInfo,
            "kwargs": {"db_file": "users.json"},
        },
        "session": {"path": "end_session", "class": Session, "kwargs": {}},
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "oidcendpoint.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "add_on": {
        "pkce": {
            "function": add_pkce_support,
            "kwargs": {
                "essential": True
            }
        }
    },
    "template_dir": "template",
}

client_yaml = """
oidc_clients:
  client1:
    # client secret is "password"
    client_secret: "Namnam"
    redirect_uris:
      - ['https://openidconnect.net/callback', '']
    response_types:
      - code
  client2:
    client_secret: "spraket"
    redirect_uris:
      - ['https://app1.example.net/foo', '']
      - ['https://app2.example.net/bar', '']
    response_types:
      - code
  client3:
    client_secret: '2222222222222222222222222222222222222222'
    redirect_uris:
      - ['https://127.0.0.1:8090/authz_cb/bobcat', '']
    post_logout_redirect_uris:
      - ['https://openidconnect.net/', '']
    response_types:
      - code
"""


def test_capabilities_default():
    endpoint_context = EndpointContext(conf)
    assert set(endpoint_context.provider_info["response_types_supported"]) == {
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "id_token token",
        "code id_token token",
    }
    assert endpoint_context.provider_info["request_uri_parameter_supported"] is True


def test_capabilities_subset1():
    _cnf = copy(conf)
    _cnf["endpoint"]["authorization_endpoint"]["kwargs"] = {"response_types_supported": ["code"]}
    endpoint_context = EndpointContext(_cnf)
    assert endpoint_context.provider_info["response_types_supported"] == ["code"]


def test_capabilities_subset2():
    _cnf = copy(conf)
    _cnf["endpoint"]["authorization_endpoint"]["kwargs"] = {
        "response_types_supported": ["code", "id_token"]
    }
    endpoint_context = EndpointContext(_cnf)
    assert set(endpoint_context.provider_info["response_types_supported"]) == {
        "code",
        "id_token",
    }


def test_capabilities_bool():
    _cnf = copy(conf)
    _cnf["endpoint"]["authorization_endpoint"]["kwargs"] = {"request_uri_parameter_supported": False}
    endpoint_context = EndpointContext(_cnf)
    assert endpoint_context.provider_info["request_uri_parameter_supported"] is False


def test_capabilities_no_support():
    _cnf = copy(conf)
    _cnf["id_token"]["kwargs"] = {"id_token_signing_alg_values_supported": "RC4"}
    with pytest.raises(ValueError):
        EndpointContext(_cnf)
    _cnf["id_token"]["kwargs"] = {}


def test_cdb():
    endpoint_context = EndpointContext(conf)
    _clients = yaml.safe_load(io.StringIO(client_yaml))
    endpoint_context.cdb = _clients["oidc_clients"]

    assert set(endpoint_context.cdb.keys()) == {"client1", "client2", "client3"}
