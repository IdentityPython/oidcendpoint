from oidcendpoint.grant import AuthorizationCode
from oidcendpoint.grant import Grant
from oidcendpoint.grant import Token
from oidcendpoint.grant import find_token


def test_access_code():
    token = AuthorizationCode('authorization_code', value="ABCD")
    assert token.issued_at
    assert token.type == "authorization_code"
    assert token.value == "ABCD"

    token.register_usage()
    #  max_usage == 1
    assert token.max_usage_reached() is True


def test_access_token():
    code = AuthorizationCode('authorization_code', value="ABCD")
    token = Token('access_token', value="1234", based_on=code.id, usage_rules={"max_usage": 2})
    assert token.issued_at
    assert token.type == "access_token"
    assert token.value == "1234"

    token.register_usage()
    #  max_usage - undefined
    assert token.max_usage_reached() is False

    token.register_usage()
    assert token.max_usage_reached() is True

    t = find_token([code, token], token.based_on)
    assert t.value == "ABCD"

    token.revoked = True
    assert token.revoked is True


def test_mint_token():
    grant = Grant()
    code = grant.mint_token("authorization_code", value="ABCD")
    access_token = grant.mint_token("access_token",
                                    value="1234",
                                    based_on=code,
                                    scope=["openid", "foo", "bar"])

    assert access_token.scope == ["openid", "foo", "bar"]


def test_grant():
    grant = Grant()
    code = grant.mint_token("authorization_code", value="ABCD")
    access_token = grant.mint_token("access_token", value="1234", based_on=code)
    refresh_token = grant.mint_token("refresh_token", value="1234", based_on=code)
    grant.revoke_token()
    assert code.revoked is True
    assert access_token.revoked is True
    assert refresh_token.revoked is True


def test_get_token():
    grant = Grant()
    code = grant.mint_token("authorization_code", value="ABCD")
    access_token = grant.mint_token("access_token",
                                    value="1234",
                                    based_on=code,
                                    scope=["openid", "foo", "bar"])


    _code = grant.get_token(code.value)
    assert _code.id == code.id

    _token = grant.get_token(access_token.value)
    assert _token.id == access_token.id



def test_grant_revoked_based_on():
    grant = Grant()
    code = grant.mint_token("authorization_code", value="ABCD")
    access_token = grant.mint_token("access_token", value="1234", based_on=code)
    refresh_token = grant.mint_token("refresh_token", value="1234", based_on=code)

    code.register_usage()
    if code.max_usage_reached():
        grant.revoke_token(based_on=code.value)

    assert code.is_active() is False
    assert access_token.is_active() is False
    assert refresh_token.is_active() is False


def test_grant_update():
    grant = Grant()
    user_info_claims = {"given_name": None, "email": None}
    grant.update(claims={"userinfo": user_info_claims})
    id_token_claims = {"email": None}
    grant.update(claims={"id_token": id_token_claims})
    introspection_claims = {"affiliation": None}
    grant.update(claims={"introspection": introspection_claims})

    assert set(grant.claims.keys()) == {"userinfo", "id_token", "introspection"}

    grant.update(resources=["https://api.example.com"])
    assert grant.resources == ["https://api.example.com"]

    grant.update(resources=["https://api.example.com",
                            "https://api.example.org"])

    assert set(grant.resources) == {"https://api.example.com",
                                    "https://api.example.org"}


def test_grant_replace():
    grant = Grant()
    grant.update(resources=["https://api.example.com"])
    assert grant.resources == ["https://api.example.com"]

    grant.replace(resources=["https://api.example.org"])

    assert set(grant.resources) == {"https://api.example.org"}


def test_revoke():
    grant = Grant()
    code = grant.mint_token("authorization_code", value="ABCD")
    access_token = grant.mint_token("access_token", value="1234", based_on=code)

    grant.revoke_token(based_on=code.value)

    assert code.is_active() is True
    assert access_token.is_active() is False

    access_token_2 = grant.mint_token("access_token",
                                      value="0987", based_on=code)

    grant.revoke_token(value=code.value, recursive=True)

    assert code.is_active() is False
    assert access_token_2.is_active() is False

