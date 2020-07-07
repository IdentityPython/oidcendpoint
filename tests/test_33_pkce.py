import io
import json
import os
import string

try:
    from random import SystemRandom as rnd
except ImportError:
    import random as rnd

import pytest
import yaml
from cryptojwt.utils import b64e
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AuthorizationRequest

from oidcendpoint.cookie import CookieDealer
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.id_token import IDToken
from oidcendpoint.oidc.add_on.pkce import CC_METHOD
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.token import AccessToken

BASECH = string.ascii_letters + string.digits + "-._~"

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

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

AUTH_REQ_DICT = AUTH_REQ.to_dict()

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())

client_yaml = """
oidc_clients:
  client_1:
    "client_secret": 'hemligt'
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


def unreserved(size=64):
    return "".join(rnd.choice(BASECH) for _ in range(size))


def _code_challenge():
    """
    PKCE aka RFC 7636
    """
    # code_verifier: string of length cv_len
    code_verifier = unreserved(64)
    _cv = code_verifier.encode()

    _method = "S256"

    # Pick hash method
    _hash_method = CC_METHOD[_method]
    # Use it on the code_verifier
    _hv = _hash_method(_cv).digest()
    # base64 encode the hash value
    code_challenge = b64e(_hv).decode("ascii")

    return {
        "code_challenge": code_challenge,
        "code_challenge_method": _method,
        "code_verifier": code_verifier,
    }


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt zebra",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "capabilities": CAPABILITIES,
            "keys": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "id_token": {
                "class": IDToken,
                "kwargs": {
                    "available_claims": {
                        "email": {"essential": True},
                        "email_verified": {"essential": True},
                    }
                },
            },
            "endpoint": {
                "authorization": {
                    "path": "{}/authorization",
                    "class": Authorization,
                    "kwargs": {},
                },
                "token": {
                    "path": "{}/token",
                    "class": AccessToken,
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_post",
                            "client_secret_basic",
                            "client_secret_jwt",
                            "private_key_jwt",
                        ]
                    },
                },
            },
            "authentication": {
                "anon": {
                    "acr": "http://www.swamid.se/policy/assurance/al1",
                    "class": "oidcendpoint.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "template_dir": "template",
            "add_on": {
                "pkce": {
                    "function": "oidcendpoint.oidc.add_on.pkce.add_pkce_support",
                    "kwargs": {"essential": True},
                }
            },
            "cookie_dealer": {
                "class": CookieDealer,
                "kwargs": {
                    "sign_key": "ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch",
                    "default_values": {
                        "name": "oidcop",
                        "domain": "127.0.0.1",
                        "path": "/",
                        "max_age": 3600,
                    },
                },
            },
        }
        endpoint_context = EndpointContext(conf)
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["oidc_clients"]
        endpoint_context.keyjar.import_jwks(
            endpoint_context.keyjar.export_jwks(True, ""), conf["issuer"]
        )
        self.authn_endpoint = endpoint_context.endpoint["authorization"]
        self.token_endpoint = endpoint_context.endpoint["token"]

    def test_parse(self):
        _cc_info = _code_challenge()
        _authn_req = AUTH_REQ.copy()
        _authn_req["code_challenge"] = _cc_info["code_challenge"]
        _authn_req["code_challenge_method"] = _cc_info["code_challenge_method"]

        _pr_resp = self.authn_endpoint.parse_request(_authn_req.to_dict())
        _resp = self.authn_endpoint.process_request(_pr_resp)

        _token_request = TOKEN_REQ.copy()
        sids = self.token_endpoint.endpoint_context.sdb.get_sid_by_kv(
            _authn_req["state"], "state"
        )
        _token_request["code"] = self.token_endpoint.endpoint_context.sdb[sids[0]][
            "code"
        ]
        _token_request["code_verifier"] = _cc_info["code_verifier"]
        _req = self.token_endpoint.parse_request(_token_request)
        assert _req
