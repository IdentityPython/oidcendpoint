import io
import json
import os
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
import yaml
from cryptojwt import KeyJar
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import b64e
from oidcmsg.exception import ParameterError
from oidcmsg.exception import URIError
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.time_util import in_a_while

from oidcendpoint.common.authorization import FORM_POST
from oidcendpoint.common.authorization import get_uri
from oidcendpoint.common.authorization import inputs
from oidcendpoint.common.authorization import join_query
from oidcendpoint.common.authorization import verify_uri
from oidcendpoint.cookie import CookieDealer
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.exception import InvalidRequest
from oidcendpoint.exception import NoSuchAuthentication
from oidcendpoint.exception import RedirectURIError
from oidcendpoint.exception import ToOld
from oidcendpoint.exception import UnknownClient
from oidcendpoint.exception import UnAuthorizedClient
from oidcendpoint.id_token import IDToken
from oidcendpoint.oauth2.authorization import Authorization
from oidcendpoint.session import SessionInfo
from oidcendpoint.user_info import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]}
    # {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

RESPONSE_TYPES_SUPPORTED = [["code"], ["token"], ["code", "token"], ["none"]]

CAPABILITIES = {
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "refresh_token",
    ]
}

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
clients:
  client_1:
    "client_secret": 'hemligtkodord'
    "redirect_uris":
        - ['https://example.com/cb', '']
    "client_salt": "salted"
    'token_endpoint_auth_method': 'client_secret_post'
    'response_types':
        - 'code'
        - 'token'
  client2:
    client_secret: "spraket"
    redirect_uris:
      - ['https://app1.example.net/foo', '']
      - ['https://app2.example.net/bar', '']
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
        }
        endpoint_context = EndpointContext(conf)
        _clients = yaml.safe_load(io.StringIO(client_yaml))
        endpoint_context.cdb = _clients["clients"]
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

    def test_do_response_code_token(self):
        """UnAuthorized Client
        """
        _orig_req = AUTH_REQ_DICT.copy()
        _orig_req["response_type"] = "code token"
        msg = ''
        _pr_resp = self.endpoint.parse_request(_orig_req)
        assert isinstance(_pr_resp, AuthorizationErrorResponse)
        assert _pr_resp["error"] == "invalid_request"

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

        with pytest.raises(KeyError):
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

        resp = self.endpoint.create_authn_response(request, "session_id")
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
        assert set(info.keys()) == {
            "response_args",
            "return_uri",
            "response_msg",
            "content_type",
            "response_placement",
        }
        assert info["response_msg"] == FORM_POST.format(
            action="https://example.com/cb",
            inputs='<input type="hidden" name="foo" value="bar"/>',
        )

    def test_response_mode_fragment(self):
        request = {"response_mode": "fragment"}
        self.endpoint.response_mode(request, fragment_enc=True)

        with pytest.raises(InvalidRequest):
            self.endpoint.response_mode(request, fragment_enc=False)

        info = self.endpoint.response_mode(request)
        assert set(info.keys()) == {"fragment_enc"}


def test_inputs():
    elems = inputs(dict(foo="bar", home="stead"))
    test_elems = (
        '<input type="hidden" name="foo" value="bar"/>',
        '<input type="hidden" name="home" value="stead"/>',
    )
    assert test_elems[0] in elems and test_elems[1] in elems


def test_join_query():
    redirect_uris = [("https://rp.example.com/cb", {"foo": ["bar"], "state": ["low"]})]
    uri = join_query(*redirect_uris[0])
    test_uri = ("https://rp.example.com/cb?", "foo=bar", "state=low")
    for i in test_uri:
        assert i in uri
