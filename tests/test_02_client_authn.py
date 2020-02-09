import base64

import pytest
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import build_keyjar
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from oidcendpoint import JWT_BEARER
from oidcendpoint.client_authn import AuthnFailure
from oidcendpoint.client_authn import BearerBody
from oidcendpoint.client_authn import BearerHeader
from oidcendpoint.client_authn import ClientSecretBasic
from oidcendpoint.client_authn import ClientSecretJWT
from oidcendpoint.client_authn import ClientSecretPost
from oidcendpoint.client_authn import JWSAuthnMethod
from oidcendpoint.client_authn import PrivateKeyJWT
from oidcendpoint.client_authn import basic_authn
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.exception import MultipleUsage
from oidcendpoint.exception import NotForMe
from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc.userinfo import UserInfo

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
    "endpoint": {
        "token": {"path": "token", "class": AccessToken, "kwargs": {}},
        "authorization": {"path": "auth", "class": Authorization, "kwargs": {}},
        "userinfo": {"path": "user", "class": UserInfo, "kwargs": {}}
    },
    "template_dir": "template",
    "jwks": {
        "private_path": "own/jwks.json",
        "key_defs": KEYDEFS,
        "uri_path": "static/jwks.json",
    },
}
client_id = "client_id"
client_secret = "a_longer_client_secret"
# Need to add the client_secret as a symmetric key bound to the client_id
KEYJAR.add_symmetric(client_id, client_secret, ["sig"])

endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
endpoint_context.cdb[client_id] = {"client_secret": client_secret}


def get_client_id_from_token(endpoint_context, token, request=None):
    if "client_id" in request:
        if request["client_id"] == endpoint_context.registration_access_token[token]:
            return request["client_id"]
    return ""


def test_client_secret_basic():
    _token = "{}:{}".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))

    authz_token = "Basic {}".format(token)

    authn_info = ClientSecretBasic(endpoint_context).verify({}, authz_token)

    assert authn_info["client_id"] == client_id


def test_client_secret_post():
    request = {"client_id": client_id, "client_secret": client_secret}

    authn_info = ClientSecretPost(endpoint_context).verify(request)

    assert authn_info["client_id"] == client_id


def test_client_secret_jwt():
    client_keyjar = KeyJar()
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]
    # The only own key the client has a this point
    client_keyjar.add_symmetric("", client_secret, ["sig"])

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
    _jwt.with_jti = True
    _assertion = _jwt.pack({"aud": [conf["issuer"]]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    authn_info = ClientSecretJWT(endpoint_context).verify(request)

    assert authn_info["client_id"] == client_id
    assert "jwt" in authn_info


def test_private_key_jwt():
    # Own dynamic keys
    client_keyjar = build_keyjar(KEYDEFS)
    # The servers keys
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]

    _jwks = client_keyjar.export_jwks()
    endpoint_context.keyjar.import_jwks(_jwks, client_id)

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="RS256")
    _jwt.with_jti = True
    _assertion = _jwt.pack({"aud": [conf["issuer"]]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    authn_info = PrivateKeyJWT(endpoint_context).verify(request)

    assert authn_info["client_id"] == client_id
    assert "jwt" in authn_info


def test_private_key_jwt_reusage_other_endpoint():
    # Own dynamic keys
    client_keyjar = build_keyjar(KEYDEFS)
    # The servers keys
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]

    _jwks = client_keyjar.export_jwks()
    endpoint_context.keyjar.import_jwks(_jwks, client_id)

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="RS256")
    _jwt.with_jti = True
    _assertion = _jwt.pack({"aud": [endpoint_context.endpoint["token"].full_path]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    # This should be OK
    PrivateKeyJWT(endpoint_context).verify(request, endpoint="token")

    # This should NOT be OK
    with pytest.raises(NotForMe):
        PrivateKeyJWT(endpoint_context).verify(request, endpoint="authorization")

    # This should NOT be OK
    with pytest.raises(MultipleUsage):
        PrivateKeyJWT(endpoint_context).verify(request, endpoint="token")


def test_private_key_jwt_auth_endpoint():
    # Own dynamic keys
    client_keyjar = build_keyjar(KEYDEFS)
    # The servers keys
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]

    _jwks = client_keyjar.export_jwks()
    endpoint_context.keyjar.import_jwks(_jwks, client_id)

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="RS256")
    _jwt.with_jti = True
    _assertion = _jwt.pack({"aud": [endpoint_context.endpoint["authorization"].full_path]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    authn_info = PrivateKeyJWT(endpoint_context).verify(request, endpoint="authorization")

    assert authn_info["client_id"] == client_id
    assert "jwt" in authn_info


def test_wrong_type():
    with pytest.raises(AuthnFailure):
        ClientSecretBasic(endpoint_context).verify({}, "Foppa toffel")


def test_csb_wrong_secret():
    _token = "{}:{}".format(client_id, "pillow")
    token = as_unicode(base64.b64encode(as_bytes(_token)))

    authz_token = "Basic {}".format(token)

    with pytest.raises(AuthnFailure):
        ClientSecretBasic(endpoint_context).verify({}, authz_token)


def test_client_secret_post_wrong_secret():
    request = {"client_id": client_id, "client_secret": "pillow"}

    with pytest.raises(AuthnFailure):
        ClientSecretPost(endpoint_context).verify(request)


def test_bearerheader():
    request = {}
    authorization_info = "Bearer 1234567890"
    assert BearerHeader(endpoint_context).verify(request, authorization_info) == {
        "token": "1234567890"
    }


def test_bearerheader_wrong_type():
    request = {}
    authorization_info = "Thrower 1234567890"
    with pytest.raises(AuthnFailure):
        BearerHeader(endpoint_context).verify(request, authorization_info)


def test_bearer_body():
    request = {"access_token": "1234567890"}
    assert BearerBody(endpoint_context).verify(request) == {"token": "1234567890"}


def test_bearer_body_no_token():
    request = {}
    with pytest.raises(AuthnFailure):
        BearerBody(endpoint_context).verify(request)


def test_jws_authn_method_wrong_key():
    client_keyjar = KeyJar()
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]
    # Fake symmetric key
    client_keyjar.add_symmetric("", "client_secret:client_secret", ["sig"])

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
    _assertion = _jwt.pack({"aud": [conf["issuer"]]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    with pytest.raises(AuthnFailure):
        JWSAuthnMethod(endpoint_context).verify(request)


def test_jws_authn_method_aud_iss():
    client_keyjar = KeyJar()
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]
    # The only own key the client has a this point
    client_keyjar.add_symmetric("", client_secret, ["sig"])

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
    # Audience is OP issuer ID
    aud = conf["issuer"]
    _assertion = _jwt.pack({"aud": [aud]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    assert JWSAuthnMethod(endpoint_context).verify(request)


def test_jws_authn_method_aud_token_endpoint():
    client_keyjar = KeyJar()
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]
    # The only own key the client has a this point
    client_keyjar.add_symmetric("", client_secret, ["sig"])

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")

    # audience is OP token endpoint - that's OK
    aud = "{}token".format(conf["issuer"])
    _assertion = _jwt.pack({"aud": [aud]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    assert JWSAuthnMethod(endpoint_context).verify(request, endpoint="token")


def test_jws_authn_method_aud_not_me():
    client_keyjar = KeyJar()
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]
    # The only own key the client has a this point
    client_keyjar.add_symmetric("", client_secret, ["sig"])

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")

    # Other audiences not OK
    aud = "https://example.org"

    _assertion = _jwt.pack({"aud": [aud]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    with pytest.raises(NotForMe):
        JWSAuthnMethod(endpoint_context).verify(request)


def test_basic_auth():
    _token = "{}:{}".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))

    res = basic_authn("Basic {}".format(token))
    assert res


def test_basic_auth_wrong_label():
    _token = "{}:{}".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))

    with pytest.raises(AuthnFailure):
        basic_authn("Expanded {}".format(token))


def test_basic_auth_wrong_token():
    _token = "{}:{}:foo".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))
    with pytest.raises(ValueError):
        basic_authn("Basic {}".format(token))

    _token = "{}:{}".format(client_id, client_secret)
    with pytest.raises(ValueError):
        basic_authn("Basic {}".format(_token))

    _token = "{}{}".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))
    with pytest.raises(ValueError):
        basic_authn("Basic {}".format(token))


def test_verify_client_jws_authn_method():
    client_keyjar = KeyJar()
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]
    # The only own key the client has a this point
    client_keyjar.add_symmetric("", client_secret, ["sig"])

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")
    # Audience is OP issuer ID
    aud = conf["issuer"]
    _assertion = _jwt.pack({"aud": [aud]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    res = verify_client(endpoint_context, request)
    assert res["method"] == "private_key_jwt"
    assert res["client_id"] == "client_id"


def test_verify_client_bearer_body():
    request = {"access_token": "1234567890", "client_id": client_id}
    endpoint_context.registration_access_token["1234567890"] = client_id
    res = verify_client(
        endpoint_context, request, get_client_id_from_token=get_client_id_from_token
    )
    assert set(res.keys()) == {"token", "method", "client_id"}
    assert res["method"] == "bearer_body"


def test_verify_client_client_secret_post():
    request = {"client_id": client_id, "client_secret": client_secret}
    res = verify_client(endpoint_context, request)
    assert set(res.keys()) == {"method", "client_id"}
    assert res["method"] == "client_secret_post"


def test_verify_client_client_secret_basic():
    _token = "{}:{}".format(client_id, client_secret)
    token = as_unicode(base64.b64encode(as_bytes(_token)))
    authz_token = "Basic {}".format(token)
    res = verify_client(endpoint_context, {}, authz_token)
    assert set(res.keys()) == {"method", "client_id"}
    assert res["method"] == "client_secret_basic"


def test_verify_client_bearer_header():
    endpoint_context.registration_access_token["1234567890"] = client_id
    token = "Bearer 1234567890"
    request = {"client_id": client_id}
    res = verify_client(
        endpoint_context,
        request,
        authorization_info=token,
        get_client_id_from_token=get_client_id_from_token,
    )

    res = verify_client(endpoint_context, request, token, get_client_id_from_token)
    assert set(res.keys()) == {"token", "method", "client_id"}
    assert res["method"] == "bearer_header"


def test_jws_authn_method_aud_userinfo_endpoint():
    client_keyjar = KeyJar()
    client_keyjar[conf["issuer"]] = KEYJAR.issuer_keys[""]
    # The only own key the client has a this point
    client_keyjar.add_symmetric("", client_secret, ["sig"])

    _jwt = JWT(client_keyjar, iss=client_id, sign_alg="HS256")

    # audience is the OP - not specifically the user info endpoint
    _assertion = _jwt.pack({"aud": [conf["issuer"]]})

    request = {"client_assertion": _assertion, "client_assertion_type": JWT_BEARER}

    assert JWSAuthnMethod(endpoint_context).verify(request, endpoint="userinfo")
