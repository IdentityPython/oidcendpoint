import pytest
from copy import copy
from requests import request

from oicmsg.key_jar import build_keyjar

from oicsrv.exception import ConfigurationError
from oicsrv.oic.authorization import Authorization
from oicsrv.oic.provider_config import ProviderConfiguration
from oicsrv.oic.registration import Registration
from oicsrv.oic.token import AccessToken
from oicsrv.oic.userinfo import UserInfo
from oicsrv.srv_info import SrvInfo
from oicsrv.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYJAR = build_keyjar(KEYDEFS)[1]

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "capabilities": {},
    "jwks": {
        'url_path': 'jwks.json',
        'local_path': 'static/jwks.json',
        'private_path': 'own/jwks.json'
    },
    'endpoint': {
        'provider_config': {
            'path': '.well-known/openid-configuration',
            'class': ProviderConfiguration,
            'kwargs': {}
        },
        'registration_endpoint': {
            'path': 'registration',
            'class': Registration,
            'kwargs': {}
        },
        'authorization_endpoint': {
            'path': 'authorization',
            'class': Authorization,
            'kwargs': {}
        },
        'token_endpoint': {
            'path': 'token',
            'class': AccessToken,
            'kwargs': {}
        },
        'userinfo_endpoint': {
            'path': 'userinfo',
            'class': UserInfo,
            'kwargs': {'db_file': 'users.json'}
        }
    },
    'authentication': [
        {
            'acr': INTERNETPROTOCOLPASSWORD,
            'name': 'NoAuthn',
            'args': {'user': 'diana'}
        }
    ]
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
