import json
import os
import time

import pytest
from cryptojwt.jws import jws
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.id_token import IDToken
from oidcendpoint.id_token import get_sign_and_encrypt_algorithms
from oidcendpoint.oidc import userinfo
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import RegistrationResponse

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERS = json.loads(open(full_path("users.json")).read())
USERINFO = UserInfo(USERS)

AREQN = AuthorizationRequest(
    response_type="code",
    client_id="client1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
    nonce="nonce",
)

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "jwks": {"key_defs": KEYDEFS, "uri_path": "static/jwks.json"},
    "jwks_uri": "https://example.com/jwks.json",
    "endpoint": {
        "authorization_endpoint": {
            "path": "{}/authorization",
            "class": Authorization,
            "kwargs": {},
        },
        "token_endpoint": {"path": "{}/token", "class": AccessToken, "kwargs": {}},
        "userinfo_endpoint": {
            "path": "{}/userinfo",
            "class": userinfo.UserInfo,
            "kwargs": {"db_file": "users.json"},
        },
    },
    "authentication": {
        "anon": {
            "acr": INTERNETPROTOCOLPASSWORD,
            "class": "oidcendpoint.user_authn.user.NoAuthn",
            "kwargs": {"user": "diana"},
        }
    },
    "userinfo": {
        "class": "oidcendpoint.user_info.UserInfo",
        "kwargs": {"db": USERS},
    },
    "client_authn": verify_client,
    "template_dir": "template",
    "id_token": {"class": IDToken, "kwargs": {"foo": "bar"}},
}


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_idtoken(self):
        self.endpoint_context = EndpointContext(conf)
        self.endpoint_context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code", "token", "code id_token", "id_token"],
        }

    def test_id_token_payload_0(self):
        session_info = {"authn_req": AREQN, "sub": "1234567890"}
        info = self.endpoint_context.idtoken.payload(session_info)
        assert info["payload"] == {"sub": "1234567890", "nonce": "nonce"}
        assert info["lifetime"] == 300

    def test_id_token_payload_1(self):
        session_info = {"authn_req": AREQN, "sub": "1234567890"}

        info = self.endpoint_context.idtoken.payload(session_info)
        assert info["payload"] == {"nonce": "nonce", "sub": "1234567890"}
        assert info["lifetime"] == 300

    def test_id_token_payload_with_code(self):
        session_info = {"authn_req": AREQN, "sub": "1234567890"}

        info = self.endpoint_context.idtoken.payload(
            session_info, code="ABCDEFGHIJKLMNOP"
        )
        assert info["payload"] == {
            "nonce": "nonce",
            "c_hash": "5-i4nCch0pDMX1VCVJHs1g",
            "sub": "1234567890",
        }
        assert info["lifetime"] == 300

    def test_id_token_payload_with_access_token(self):
        session_info = {"authn_req": AREQN, "sub": "1234567890"}

        info = self.endpoint_context.idtoken.payload(
            session_info, access_token="012ABCDEFGHIJKLMNOP"
        )
        assert info["payload"] == {
            "nonce": "nonce",
            "at_hash": "bKkyhbn1CC8IMdavzOV-Qg",
            "sub": "1234567890",
        }
        assert info["lifetime"] == 300

    def test_id_token_payload_with_code_and_access_token(self):
        session_info = {"authn_req": AREQN, "sub": "1234567890"}

        info = self.endpoint_context.idtoken.payload(
            session_info, access_token="012ABCDEFGHIJKLMNOP", code="ABCDEFGHIJKLMNOP"
        )
        assert info["payload"] == {
            "nonce": "nonce",
            "at_hash": "bKkyhbn1CC8IMdavzOV-Qg",
            "c_hash": "5-i4nCch0pDMX1VCVJHs1g",
            "sub": "1234567890",
        }
        assert info["lifetime"] == 300

    def test_id_token_payload_with_userinfo(self):
        session_info = {"authn_req": AREQN, "sub": "1234567890"}

        info = self.endpoint_context.idtoken.payload(
            session_info, user_info={"given_name": "Diana"}
        )
        assert info["payload"] == {
            "nonce": "nonce",
            "given_name": "Diana",
            "sub": "1234567890",
        }
        assert info["lifetime"] == 300

    def test_id_token_payload_many_0(self):
        session_info = {"authn_req": AREQN, "sub": "1234567890"}

        info = self.endpoint_context.idtoken.payload(
            session_info,
            user_info={"given_name": "Diana"},
            access_token="012ABCDEFGHIJKLMNOP",
            code="ABCDEFGHIJKLMNOP",
        )
        assert info["payload"] == {
            "nonce": "nonce",
            "given_name": "Diana",
            "at_hash": "bKkyhbn1CC8IMdavzOV-Qg",
            "c_hash": "5-i4nCch0pDMX1VCVJHs1g",
            "sub": "1234567890",
        }
        assert info["lifetime"] == 300

    def test_sign_encrypt_id_token(self):
        client_info = RegistrationResponse(
            id_token_signed_response_alg="RS512", client_id="client_1"
        )
        session_info = {
            "authn_req": AREQN,
            "sub": "sub",
            "authn_event": {"authn_info": "loa2", "authn_time": time.time()},
        }

        self.endpoint_context.jwx_def["signing_alg"] = {"id_token": "RS384"}
        self.endpoint_context.cdb["client_1"] = client_info.to_dict()

        _token = self.endpoint_context.idtoken.sign_encrypt(
            session_info, "client_1", sign=True
        )
        assert _token

        _jws = jws.factory(_token)

        assert _jws.jwt.headers["alg"] == "RS512"

        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)

        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert isinstance(res, dict)
        assert res["aud"] == ["client_1"]

    def test_get_sign_algorithm(self):
        client_info = RegistrationResponse()
        endpoint_context = EndpointContext(conf)
        algs = get_sign_and_encrypt_algorithms(
            endpoint_context, client_info, "id_token", sign=True
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS256"}

    def test_no_default_encrypt_algorithms(self):
        client_info = RegistrationResponse()
        endpoint_context = EndpointContext(conf)
        args = get_sign_and_encrypt_algorithms(
            endpoint_context, client_info, "id_token", sign=True, encrypt=True
        )
        assert args["sign_alg"] == "RS256"
        assert args["enc_enc"] == "A128CBC-HS256"
        assert args["enc_alg"] == "RSA1_5"

    def test_get_sign_algorithm_2(self):
        client_info = RegistrationResponse(id_token_signed_response_alg="RS512")
        endpoint_context = EndpointContext(conf)
        algs = get_sign_and_encrypt_algorithms(
            endpoint_context, client_info, "id_token", sign=True
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS512"}

    def test_get_sign_algorithm_3(self):
        client_info = RegistrationResponse()
        endpoint_context = EndpointContext(conf)
        endpoint_context.jwx_def["signing_alg"] = {"id_token": "RS384"}

        algs = get_sign_and_encrypt_algorithms(
            endpoint_context, client_info, "id_token", sign=True
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS384"}

    def test_get_sign_algorithm_4(self):
        client_info = RegistrationResponse(id_token_signed_response_alg="RS512")
        endpoint_context = EndpointContext(conf)
        endpoint_context.jwx_def["signing_alg"] = {"id_token": "RS384"}

        algs = get_sign_and_encrypt_algorithms(
            endpoint_context, client_info, "id_token", sign=True
        )
        # default signing alg
        assert algs == {"sign": True, "encrypt": False, "sign_alg": "RS512"}

    def test_available_claims(self):
        session_info = {
            "authn_req": AREQN,
            "sub": "sub",
            "authn_event": {
                "authn_info": "loa2",
                "authn_time": time.time(),
                "uid": "diana"
            },
        }
        self.endpoint_context.idtoken.kwargs['available_claims'] = {
            "nickname": {"essential": True}
        }
        req = {"client_id": "client_1"}
        _token = self.endpoint_context.idtoken.make(req, session_info)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "nickname" in res

    def test_no_available_claims(self):
        session_info = {
            "authn_req": AREQN,
            "sub": "sub",
            "authn_event": {
                "authn_info": "loa2",
                "authn_time": time.time(),
                "uid": "diana"
            },
        }
        req = {"client_id": "client_1"}
        _token = self.endpoint_context.idtoken.make(req, session_info)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "nickname" not in res

    def test_client_claims(self):
        session_info = {
            "authn_req": AREQN,
            "sub": "sub",
            "authn_event": {
                "authn_info": "loa2",
                "authn_time": time.time(),
                "uid": "diana"
            },
        }
        self.endpoint_context.idtoken.enable_claims_per_client = True
        self.endpoint_context.cdb["client_1"]['id_token_claims'] = {
            "address": None
        }
        req = {"client_id": "client_1"}
        _token = self.endpoint_context.idtoken.make(req, session_info)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "address" in res
        assert "nickname" not in res

    def test_client_claims_with_default(self):
        session_info = {
            "authn_req": AREQN,
            "sub": "sub",
            "authn_event": {
                "authn_info": "loa2",
                "authn_time": time.time(),
                "uid": "diana"
            },
        }
        self.endpoint_context.cdb["client_1"]['id_token_claims'] = {
            "address": None
        }
        self.endpoint_context.idtoken.kwargs['available_claims'] = {
            "nickname": {"essential": True}
        }
        self.endpoint_context.idtoken.enable_claims_per_client = True
        req = {"client_id": "client_1"}
        _token = self.endpoint_context.idtoken.make(req, session_info)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "address" in res
        assert "nickname" in res

    def test_client_claims_disabled(self):
        # enable_claims_per_client defaults to False
        session_info = {
            "authn_req": AREQN,
            "sub": "sub",
            "authn_event": {
                "authn_info": "loa2",
                "authn_time": time.time(),
                "uid": "diana"
            },
        }
        self.endpoint_context.cdb["client_1"]['id_token_claims'] = {
            "address": None
        }
        req = {"client_id": "client_1"}
        _token = self.endpoint_context.idtoken.make(req, session_info)
        assert _token
        client_keyjar = KeyJar()
        _jwks = self.endpoint_context.keyjar.export_jwks()
        client_keyjar.import_jwks(_jwks, self.endpoint_context.issuer)
        _jwt = JWT(key_jar=client_keyjar, iss="client_1")
        res = _jwt.unpack(_token)
        assert "address" not in res
        assert "nickname" not in res
