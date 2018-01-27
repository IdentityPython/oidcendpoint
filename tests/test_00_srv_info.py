import pytest
from copy import copy
from oicmsg.key_jar import build_keyjar
from oicsrv.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from requests import request

from oicsrv.exception import ConfigurationError
from oicsrv.srv_info import SrvInfo

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYJAR = build_keyjar(KEYDEFS)[1]

conf = {
    "base_url": "https://example.com",
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "capabilities": {},
    "jwks_uri": 'https://example.com/jwks.json',
    "endpoint": {
        'registration': 'registration',
        'authorization': 'authz',
        'token': 'token',
        'userinfo': 'userinfo'
    },
    "authentication": [{
        'acr': INTERNETPROTOCOLPASSWORD,
        'name': 'NoAuthn',
        'args': {'user': 'diana'}
    }]
}


def test_capabilities_default():
    srv_info = SrvInfo(conf, keyjar=KEYJAR, httplib=request)
    assert set(srv_info.provider_info['response_types_supported']) == {
        'code', 'token', 'id_token', 'code token', 'code id_token',
        'id_token token', 'code token id_token', 'none'}
    assert srv_info.provider_info["request_uri_parameter_supported"] is True


def test_capabilities_subset1():
    _cnf = copy(conf)
    _cnf['capabilities'] = {'response_types_supported': 'code'}
    srv_info = SrvInfo(_cnf, keyjar=KEYJAR, httplib=request)
    assert srv_info.provider_info['response_types_supported'] == ['code']


def test_capabilities_subset2():
    _cnf = copy(conf)
    _cnf['capabilities'] = {'response_types_supported': ['code', 'id_token']}
    srv_info = SrvInfo(_cnf, keyjar=KEYJAR, httplib=request)
    assert set(srv_info.provider_info['response_types_supported']) == {
        'code', 'id_token'}


def test_capabilities_bool():
    _cnf = copy(conf)
    _cnf['capabilities'] = {'request_uri_parameter_supported': False}
    srv_info = SrvInfo(_cnf, keyjar=KEYJAR, httplib=request)
    assert srv_info.provider_info["request_uri_parameter_supported"] is False


def test_capabilities_no_support():
    _cnf = copy(conf)
    _cnf['capabilities'] = {'id_token_signing_alg_values_supported': 'RC4'}
    with pytest.raises(ConfigurationError):
        SrvInfo(_cnf, keyjar=KEYJAR, httplib=request)
