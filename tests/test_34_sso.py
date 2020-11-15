import io
import json
import os

import pytest
import yaml
from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg.oidc import AuthorizationRequest

from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn
from oidcendpoint.user_authn.user import UserPassJinja2
from oidcendpoint.util import JSONDictDB

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]}
    # {"type": "EC", "crv": "P-256", "use": ["sig"]}
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
    "subject_types_supported": ["public", "pairwise"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ],
}

CLAIMS = {"id_token": {"given_name": {"essential": True}, "nickname": None}}

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type="code",
)

AUTH_REQ_DICT = AUTH_REQ.to_dict()

AUTH_REQ_2 = AuthorizationRequest(
    client_id="client3",
    redirect_uri="https://127.0.0.1:8090/authz_cb/bobcat",
    scope=["openid"],
    state="STATE2",
    response_type="code",
)

AUTH_REQ_3 = AuthorizationRequest(
    client_id="client2",
    redirect_uri="https://app1.example.net/foo",
    scope=["openid"],
    state="STATE3",
    response_type="code",
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())

client_yaml = """
oidc_clients:
  client_1:
    "client_secret": 'hemligtkodord'
    "redirect_uris": 
        - ['https://example.com/cb', '']
    "client_salt": "salted"
    'token_endpoint_auth_method': 'client_secret_post'
    'response_types': 
        - 'code'
        - 'token'
        - 'code id_token'
        - 'id_token'
        - 'code id_token token'
  client2:
    client_secret: "spraket_sr.se"
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


class TestUserAuthn(object):
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {
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
                }
            },
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "authentication": {
                "anon": {
                    "acr": UNSPECIFIED,
                    "class": NoAuthn,
                    "kwargs": {"user": "diana"},
                },
            },
            "cookie_dealer": {
                "class": "oidcendpoint.cookie.CookieDealer",
                "kwargs": {
                    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                    "default_values": {
                        "name": "oidc_xx",
                        "domain": "example.com",
                        "path": "/",
                        "max_age": 3600,
                    },
                },
            },
            "template_dir": "template",
        }
        endpoint_context = EndpointContext(conf)
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["oidc_clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )
        self.endpoint = endpoint_context.endpoint["authorization"]

        self.rp_keyjar = KeyJar()
        self.rp_keyjar.add_symmetric("client_1", "hemligtkodord1234567890")
        self.endpoint.endpoint_context.keyjar.add_symmetric(
            "client_1", "hemligtkodord1234567890"
        )

    def test_sso(self):
        request = self.endpoint.parse_request(AUTH_REQ_DICT)
        redirect_uri = request["redirect_uri"]
        cinfo = self.endpoint.endpoint_context.cdb[request["client_id"]]
        info = self.endpoint.setup_auth(request, redirect_uri, cinfo, cookie=None)
        # info = self.endpoint.process_request(request)

        assert "user" in info

        res = self.endpoint.authz_part2(info["user"], request, cookie="")
        assert res
        cookie = res["cookie"]

        # second login
        request = self.endpoint.parse_request(AUTH_REQ_2.to_dict())
        redirect_uri = request["redirect_uri"]
        cinfo = self.endpoint.endpoint_context.cdb[request["client_id"]]
        info = self.endpoint.setup_auth(request, redirect_uri, cinfo, cookie=cookie[0])

        assert set(info.keys()) == {"authn_event", "identity", "user"}
        assert info["user"] == "diana"

        res = self.endpoint.authz_part2(info["user"], request, cookie="")
        cookie = res["cookie"]

        # third login
        request = self.endpoint.parse_request(AUTH_REQ_3.to_dict())
        redirect_uri = request["redirect_uri"]
        cinfo = self.endpoint.endpoint_context.cdb[request["client_id"]]
        info = self.endpoint.setup_auth(request, redirect_uri, cinfo, cookie=cookie[0])

        assert set(info.keys()) == {"authn_event", "identity", "user"}
        assert info["user"] == "diana"

        self.endpoint.authz_part2(info["user"], request, cookie="")

        user_session_info = self.endpoint.endpoint_context.session_manager.get(["diana"])
        assert len(user_session_info["subordinate"]) == 3
        assert set(user_session_info["subordinate"]) == {"client_1", "client2", "client3"}
