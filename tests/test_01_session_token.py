from oidcmsg.time_util import time_sans_frac

from oidcendpoint.session.token import AccessToken
from oidcendpoint.session.token import AuthorizationCode


def test_authorization_code_default():
    code = AuthorizationCode(value="ABCD")
    assert code.usage_rules["max_usage"] == 1
    assert code.usage_rules["supports_minting"] == ["access_token",
                                                    "refresh_token"]


def test_authorization_code_usage():
    code = AuthorizationCode(value="ABCD",
                             usage_rules={
                                 "supports_minting": ["access_token"],
                                 "max_usage": 1
                             })

    assert code.usage_rules["max_usage"] == 1
    assert code.usage_rules["supports_minting"] == ["access_token"]


def test_authorization_code_extras():
    code = AuthorizationCode(value="ABCD",
                             scope=["openid", "foo", "bar"],
                             claims={"userinfo": {"given_name": None}},
                             resources=["https://api.example.com"])

    assert code.scope == ["openid", "foo", "bar"]
    assert code.claims == {"userinfo": {"given_name": None}}
    assert code.resources == ["https://api.example.com"]


def test_to_from_json():
    code = AuthorizationCode(value="ABCD",
                             scope=["openid", "foo", "bar"],
                             claims={"userinfo": {"given_name": None}},
                             resources=["https://api.example.com"])

    _json_str = code.to_json()

    _new_code = AuthorizationCode().from_json(_json_str)

    for attr in AuthorizationCode.attributes:
        assert getattr(code, attr) == getattr(_new_code, attr)


def test_supports_minting():
    code = AuthorizationCode(value="ABCD")
    assert code.supports_minting('access_token')
    assert code.supports_minting('refresh_token')
    assert code.supports_minting("authorization_code") is False


def test_usage():
    token = AccessToken(usage_rules={"max_usage": 2})

    token.register_usage()
    assert token.has_been_used()
    assert token.used == 1
    assert token.max_usage_reached() is False

    token.register_usage()
    assert token.max_usage_reached()

    token.register_usage()
    assert token.used == 3
    assert token.max_usage_reached()


def test_is_active_usage():
    token = AccessToken(usage_rules={"max_usage": 2})

    token.register_usage()
    token.register_usage()
    assert token.is_active() is False


def test_is_active_revoke():
    token = AccessToken(usage_rules={"max_usage": 2})
    token.revoke()
    assert token.is_active() is False


def test_is_active_expired():
    token = AccessToken(usage_rules={"max_usage": 2})
    token.expires_at = time_sans_frac() - 60
    assert token.is_active() is False
