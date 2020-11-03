from oidcendpoint.grant import AuthorizationCode
from oidcendpoint.grant import find_token
from oidcendpoint.grant import Grant
from oidcendpoint.grant import Token


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


def test_grant():
    grant = Grant()
    code = grant.mint_token("authorization_code", value="ABCD")
    access_token = grant.mint_token("access_token", value="1234", based_on=code.id)
    refresh_token = grant.mint_token("refresh_token", value="1234", based_on=code.id)
    grant.revoke()
    assert code.revoked is True
    assert access_token.revoked is True
    assert refresh_token.revoked is True


def test_grant_revoked_based_on():
    grant = Grant()
    code = grant.mint_token("authorization_code", value="ABCD")
    access_token = grant.mint_token("access_token", value="1234", based_on=code.id)
    refresh_token = grant.mint_token("refresh_token", value="1234", based_on=code.id)

    code.register_usage()
    if code.max_usage_reached():
        grant.revoke_all_based_on(code.id)

    assert code.is_active() is False
    assert access_token.is_active() is False
    assert refresh_token.is_active() is False
