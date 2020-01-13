import io
import json
import os
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
import responses
import yaml
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import b64e
from oidcendpoint.common.authorization import FORM_POST
from oidcendpoint.common.authorization import join_query
from oidcendpoint.common.authorization import verify_uri
from oidcendpoint.cookie import CookieDealer
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.exception import InvalidRequest
from oidcendpoint.exception import NoSuchAuthentication
from oidcendpoint.exception import RedirectURIError
from oidcendpoint.exception import ToOld
from oidcendpoint.exception import UnknownClient
from oidcendpoint.id_token import IDToken
from oidcendpoint.login_hint import LoginHint2Acrs
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.authorization import acr_claims
from oidcendpoint.oidc.authorization import create_authn_response
from oidcendpoint.oidc.authorization import get_uri
from oidcendpoint.oidc.authorization import inputs
from oidcendpoint.oidc.authorization import re_authenticate
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.session import SessionInfo
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_authn.authn_context import init_method
from oidcendpoint.user_authn.user import NoAuthn
from oidcendpoint.user_authn.user import UserAuthnMethod
from oidcendpoint.user_info import UserInfo
from oidcmsg.exception import ParameterError
from oidcmsg.exception import URIError
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc import verify_id_token
from oidcmsg.time_util import in_a_while

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
    ]
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

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_db = json.loads(open(full_path("users.json")).read())


class SimpleCookieDealer(object):
    def __init__(self, name=""):
        self.name = name

    def create_cookie(self, value, typ, **kwargs):
        cookie = SimpleCookie()
        timestamp = str(utc_time_sans_frac())

        _payload = "::".join([value, timestamp, typ])

        bytes_load = _payload.encode("utf-8")
        bytes_timestamp = timestamp.encode("utf-8")

        cookie_payload = [bytes_load, bytes_timestamp]
        cookie[self.name] = (b"|".join(cookie_payload)).decode("utf-8")
        try:
            ttl = kwargs["ttl"]
        except KeyError:
            pass
        else:
            cookie[self.name]["expires"] = in_a_while(seconds=ttl)

        return cookie

    @staticmethod
    def get_cookie_value(cookie=None, cookie_name=None):
        if cookie is None or cookie_name is None:
            return None
        else:
            try:
                info, timestamp = cookie[cookie_name].split("|")
            except (TypeError, AssertionError):
                return None
            else:
                value = info.split("::")
                if timestamp == value[1]:
                    return value
        return None


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
            "jwks": {"uri_path": "static/jwks.json", "key_defs": KEYDEFS},
            "id_token": {
                "class": IDToken,
                "kwargs": {
                    "default_claims": {
                        "email": {"essential": True},
                        "email_verified": {"essential": True},
                    }
                },
            },
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
                "token": {
                    "path": "token",
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
                "userinfo": {
                    "path": "userinfo",
                    "class": userinfo.UserInfo,
                    "kwargs": {
                        "db_file": "users.json",
                        "claim_types_supported": [
                            "normal",
                            "aggregated",
                            "distributed",
                        ],
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
            "userinfo": {"class": UserInfo, "kwargs": {"db": USERINFO_db}},
            "template_dir": "template",
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
            "login_hint2acrs": {
                "class": LoginHint2Acrs,
                "kwargs": {"scheme_map": {"email": [INTERNETPROTOCOLPASSWORD]}},
            },
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

    def test_init(self):
        assert self.endpoint

    def test_parse(self):
        _req = self.endpoint.parse_request(AUTH_REQ_DICT)

        assert isinstance(_req, AuthorizationRequest)
        assert set(_req.keys()) == set(AUTH_REQ.keys())

    def test_process_request(self):
        _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
        _resp = self.endpoint.process_request(_pr_resp)
        assert set(_resp.keys()) == {
            "response_args",
            "fragment_enc",
            "return_uri",
            "cookie",
        }

    def test_do_response_code(self):
        _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
        _resp = self.endpoint.process_request(_pr_resp)
        msg = self.endpoint.do_response(**_resp)
        assert isinstance(msg, dict)
        _msg = parse_qs(msg["response"])
        assert _msg
        part = urlparse(msg["response"])
        assert part.fragment == ""
        assert part.query
        _query = parse_qs(part.query)
        assert _query
        assert "code" in _query

    def test_do_response_id_token_no_nonce(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "id_token"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        # Missing nonce
        assert isinstance(_pr_resp, ResponseMessage)

    def test_do_response_id_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "id_token"
        _orig_req["nonce"] = "rnd_nonce"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        _resp = self.endpoint.process_request(_pr_resp)
        msg = self.endpoint.do_response(**_resp)
        assert isinstance(msg, dict)
        part = urlparse(msg["response"])
        assert part.query == ""
        assert part.fragment
        _frag_msg = parse_qs(part.fragment)
        assert _frag_msg
        assert "id_token" in _frag_msg
        assert "code" not in _frag_msg
        assert "token" not in _frag_msg

    def test_do_response_id_token_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "id_token token"
        _orig_req["nonce"] = "rnd_nonce"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        _resp = self.endpoint.process_request(_pr_resp)
        msg = self.endpoint.do_response(response_msg=_resp)
        assert isinstance(msg, dict)
        assert msg["response"]["error"] == "invalid_request"

    def test_do_response_code_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "code token"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        _resp = self.endpoint.process_request(_pr_resp)
        msg = self.endpoint.do_response(response_msg=_resp)
        assert isinstance(msg, dict)
        assert msg["response"]["error"] == "invalid_request"

    def test_do_response_code_id_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "code id_token"
        _orig_req["nonce"] = "rnd_nonce"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        _resp = self.endpoint.process_request(_pr_resp)
        msg = self.endpoint.do_response(**_resp)
        assert isinstance(msg, dict)
        part = urlparse(msg["response"])
        assert part.query == ""
        assert part.fragment
        _frag_msg = parse_qs(part.fragment)
        assert _frag_msg
        assert "id_token" in _frag_msg
        assert "code" in _frag_msg
        assert "access_token" not in _frag_msg

    def test_do_response_code_id_token_token(self):
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "code id_token token"
        _orig_req["nonce"] = "rnd_nonce"
        _pr_resp = self.endpoint.parse_request(_orig_req)
        _resp = self.endpoint.process_request(_pr_resp)
        msg = self.endpoint.do_response(**_resp)
        assert isinstance(msg, dict)
        part = urlparse(msg["response"])
        assert part.query == ""
        assert part.fragment
        _frag_msg = parse_qs(part.fragment)
        assert _frag_msg
        assert "id_token" in _frag_msg
        assert "code" in _frag_msg
        assert "access_token" in _frag_msg

    def test_id_token_claims(self):
        _req = AUTH_REQ_DICT.copy()
        _req["claims"] = CLAIMS
        _req["response_type"] = "code id_token token"
        _req["nonce"] = "rnd_nonce"
        _pr_resp = self.endpoint.parse_request(_req)
        _resp = self.endpoint.process_request(_pr_resp)
        idt = verify_id_token(
            _resp["response_args"], keyjar=self.endpoint.endpoint_context.keyjar
        )
        assert idt
        # from claims
        assert "given_name" in _resp["response_args"]["__verified_id_token"]
        # from config
        assert "email" in _resp["response_args"]["__verified_id_token"]

    def test_re_authenticate(self):
        request = {"prompt": "login"}
        authn = UserAuthnMethod(self.endpoint.endpoint_context)
        assert re_authenticate(request, authn)

    def test_id_token_acr(self):
        _req = AUTH_REQ_DICT.copy()
        _req["claims"] = {
            "id_token": {"acr": {"value": "http://www.swamid.se/policy/assurance/al1"}}
        }
        _req["response_type"] = "code id_token token"
        _req["nonce"] = "rnd_nonce"
        _pr_resp = self.endpoint.parse_request(_req)
        _resp = self.endpoint.process_request(_pr_resp)
        res = verify_id_token(
            _resp["response_args"], keyjar=self.endpoint.endpoint_context.keyjar
        )
        assert res
        res = _resp["response_args"][verified_claim_name("id_token")]
        assert res["acr"] == "http://www.swamid.se/policy/assurance/al1"

    def test_verify_uri_unknown_client(self):
        request = {"redirect_uri": "https://rp.example.com/cb"}
        with pytest.raises(UnknownClient):
            verify_uri(self.endpoint.endpoint_context, request, "redirect_uri")

    def test_verify_uri_fragment(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {"redirect_uri": ["https://rp.example.com/auth_cb"]}
        request = {"redirect_uri": "https://rp.example.com/cb#foobar"}
        with pytest.raises(URIError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_noregistered(self):
        _ec = self.endpoint.endpoint_context
        request = {"redirect_uri": "https://rp.example.com/cb"}

        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_unregistered(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/auth_cb", {})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb"}

        with pytest.raises(RedirectURIError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_match(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}

        verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_mismatch(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bob"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar&foo=kex"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar&level=low"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_missing(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {
            "redirect_uris": [
                ("https://rp.example.com/cb", {"foo": ["bar"], "state": ["low"]})
            ]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_qp_missing_val(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {
            "redirect_uris": [("https://rp.example.com/cb", {"foo": ["bar", "low"]})]
        }

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bar"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_verify_uri_no_registered_qp(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"redirect_uri": "https://rp.example.com/cb?foo=bob"}
        with pytest.raises(ValueError):
            verify_uri(_ec, request, "redirect_uri", "client_id")

    def test_get_uri(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {
            "redirect_uri": "https://rp.example.com/cb",
            "client_id": "client_id",
        }

        assert get_uri(_ec, request, "redirect_uri") == "https://rp.example.com/cb"

    def test_get_uri_no_redirect_uri(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"client_id": "client_id"}

        assert get_uri(_ec, request, "redirect_uri") == "https://rp.example.com/cb"

    def test_get_uri_no_registered(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {"redirect_uris": [("https://rp.example.com/cb", {})]}

        request = {"client_id": "client_id"}

        with pytest.raises(ParameterError):
            get_uri(_ec, request, "post_logout_redirect_uri")

    def test_get_uri_more_then_one_registered(self):
        _ec = self.endpoint.endpoint_context
        _ec.cdb["client_id"] = {
            "redirect_uris": [
                ("https://rp.example.com/cb", {}),
                ("https://rp.example.org/authz_cb", {"foo": "bar"}),
            ]
        }

        request = {"client_id": "client_id"}

        with pytest.raises(ParameterError):
            get_uri(_ec, request, "redirect_uri")

    def test_create_authn_response(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )

        _ec = self.endpoint.endpoint_context
        _ec.sdb["session_id"] = SessionInfo(
            authn_req=request,
            uid="diana",
            sub="abcdefghijkl",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
            },
        )
        _ec.cdb["client_id"] = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "ES256",
        }

        resp = create_authn_response(self.endpoint, request, "session_id")
        assert isinstance(resp["response_args"], AuthorizationErrorResponse)

    def test_setup_auth(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }

        kaka = self.endpoint.endpoint_context.cookie_dealer.create_cookie(
            "value", "sso"
        )

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, kaka)
        assert set(res.keys()) == {"authn_event", "identity", "user"}

    def test_setup_auth_error(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }

        item = self.endpoint.endpoint_context.authn_broker.db["anon"]
        item["method"].fail = NoSuchAuthentication

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"function", "args"}

        item["method"].fail = ToOld

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"function", "args"}

        item["method"].file = ""

    def test_setup_auth_user(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }
        _ec = self.endpoint.endpoint_context
        _ec.sdb["session_id"] = SessionInfo(
            authn_req=request,
            uid="diana",
            sub="abcdefghijkl",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
            },
        )

        item = _ec.authn_broker.db["anon"]
        item["method"].user = b64e(
            as_bytes(json.dumps({"uid": "krall", "sid": "session_id"}))
        )

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"authn_event", "identity", "user"}
        assert res["identity"]["uid"] == "krall"

    def test_setup_auth_session_revoked(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }
        _ec = self.endpoint.endpoint_context
        _ec.sdb["session_id"] = SessionInfo(
            authn_req=request,
            uid="diana",
            sub="abcdefghijkl",
            authn_event={
                "authn_info": "loa1",
                "uid": "diana",
                "authn_time": utc_time_sans_frac(),
            },
            revoked=True,
        )

        item = _ec.authn_broker.db["anon"]
        item["method"].user = b64e(
            as_bytes(json.dumps({"uid": "krall", "sid": "session_id"}))
        )

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"args", "function"}

    def test_response_mode_form_post(self):
        request = {"response_mode": "form_post"}
        info = {
            "response_args": AuthorizationResponse(foo="bar"),
            "return_uri": "https://example.com/cb",
        }
        info = self.endpoint.response_mode(request, **info)
        assert set(info.keys()) == {"response_args", "return_uri", "response_msg",
                                    "content_type", "response_placement"}
        assert info["response_msg"] == FORM_POST.format(
            action="https://example.com/cb",
            inputs='<input type="hidden" name="foo" value="bar"/>',
        )

    def test_do_response_code_form_post(self):
        _req = AUTH_REQ_DICT.copy()
        _req["response_mode"] = "form_post"
        _pr_resp = self.endpoint.parse_request(_req)
        _resp = self.endpoint.process_request(_pr_resp)
        msg = self.endpoint.do_response(**_resp)
        assert ('Content-type', 'text/html') in msg["http_headers"]
        assert "response_placement" in msg

    def test_response_mode_fragment(self):
        request = {"response_mode": "fragment"}
        self.endpoint.response_mode(request, fragment_enc=True)

        with pytest.raises(InvalidRequest):
            self.endpoint.response_mode(request, fragment_enc=False)

        info = self.endpoint.response_mode(request)
        assert set(info.keys()) == {"fragment_enc"}

    def test_check_session_iframe(self):
        self.endpoint.endpoint_context.provider_info[
            "check_session_iframe"
        ] = "https://example.com/csi"
        _pr_resp = self.endpoint.parse_request(AUTH_REQ_DICT)
        _resp = self.endpoint.process_request(_pr_resp)
        assert "session_state" in _resp["response_args"]

    def test_setup_auth_login_hint(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
            login_hint="tel:0907865204",
        )
        redirect_uri = request["redirect_uri"]
        cinfo = {
            "client_id": "client_id",
            "redirect_uris": [("https://rp.example.com/cb", {})],
            "id_token_signed_response_alg": "RS256",
        }

        item = self.endpoint.endpoint_context.authn_broker.db["anon"]
        item["method"].fail = NoSuchAuthentication

        res = self.endpoint.setup_auth(request, redirect_uri, cinfo, None)
        assert set(res.keys()) == {"function", "args"}
        assert "login_hint" in res["args"]

    def test_setup_auth_login_hint2acrs(self):
        request = AuthorizationRequest(
            client_id="client_id",
            redirect_uri="https://rp.example.com/cb",
            response_type=["id_token"],
            state="state",
            nonce="nonce",
            scope="openid",
            login_hint="email:foo@bar",
        )
        redirect_uri = request["redirect_uri"]

        method_spec = {
            "acr": INTERNETPROTOCOLPASSWORD,
            "kwargs": {"user": "knoll"},
            "class": NoAuthn,
        }
        self.endpoint.endpoint_context.authn_broker["foo"] = init_method(
            method_spec, None
        )

        item = self.endpoint.endpoint_context.authn_broker.db["anon"]
        item["method"].fail = NoSuchAuthentication
        item = self.endpoint.endpoint_context.authn_broker.db["foo"]
        item["method"].fail = NoSuchAuthentication

        res = self.endpoint.pick_authn_method(request, redirect_uri)
        assert set(res.keys()) == {"method", "acr"}
        assert res["acr"] == INTERNETPROTOCOLPASSWORD
        assert isinstance(res["method"], NoAuthn)
        assert res["method"].user == "knoll"

    def test_post_logout_uri(self):
        pass

    def test_parse_request(self):
        _jwt = JWT(key_jar=self.rp_keyjar, iss="client_1", sign_alg="HS256")
        _jws = _jwt.pack(
            AUTH_REQ_DICT, aud=self.endpoint.endpoint_context.provider_info["issuer"]
        )
        # -----------------
        _req = self.endpoint.parse_request(
            {
                "request": _jws,
                "redirect_uri": AUTH_REQ.get("redirect_uri"),
                "response_type": AUTH_REQ.get("response_type"),
                "client_id": AUTH_REQ.get("client_id"),
                "scope": AUTH_REQ.get("scope"),
            }
        )
        assert "__verified_request" in _req

    def test_parse_request_uri(self):
        _jwt = JWT(key_jar=self.rp_keyjar, iss="client_1", sign_alg="HS256")
        _jws = _jwt.pack(
            AUTH_REQ_DICT, aud=self.endpoint.endpoint_context.provider_info["issuer"]
        )

        request_uri = "https://client.example.com/req"
        # -----------------
        with responses.RequestsMock() as rsps:
            rsps.add("GET", request_uri, body=_jws, status=200)
            _req = self.endpoint.parse_request(
                {
                    "request_uri": request_uri,
                    "redirect_uri": AUTH_REQ.get("redirect_uri"),
                    "response_type": AUTH_REQ.get("response_type"),
                    "client_id": AUTH_REQ.get("client_id"),
                    "scope": AUTH_REQ.get("scope"),
                }
            )

        assert "__verified_request" in _req


def test_inputs():
    elems = inputs(dict(foo="bar", home="stead"))
    test_elems = (
        '<input type="hidden" name="foo" value="bar"/>',
        '<input type="hidden" name="home" value="stead"/>',
    )
    assert test_elems[0] in elems and test_elems[1] in elems


def test_acr_claims():
    assert acr_claims({"claims": {"id_token": {"acr": {"value": "foo"}}}}) == ["foo"]
    assert acr_claims(
        {"claims": {"id_token": {"acr": {"values": ["foo", "bar"]}}}}
    ) == ["foo", "bar"]
    assert acr_claims({"claims": {"id_token": {"acr": {"values": ["foo"]}}}}) == ["foo"]
    assert acr_claims({"claims": {"id_token": {"acr": {"essential": True}}}}) is None


def test_join_query():
    redirect_uris = [("https://rp.example.com/cb", {"foo": ["bar"], "state": ["low"]})]
    uri = join_query(*redirect_uris[0])
    test_uri = ("https://rp.example.com/cb?", "foo=bar", "state=low")
    for i in test_uri:
        assert i in uri
