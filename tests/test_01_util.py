import pytest
from cryptojwt.exception import UnknownAlgorithm
from oicmsg.oic import RegistrationResponse
from requests import request

from oicsrv.srv_info import SrvInfo
from oicsrv.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

from oicsrv.util import get_sign_and_encrypt_algorithms

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


def test_get_sign_algorithm():
    client_info = RegistrationResponse()
    srv_info = SrvInfo(conf, httplib=request)
    algs = get_sign_and_encrypt_algorithms(srv_info, client_info, 'id_token',
                                           sign=True)
    # default signing alg
    assert algs == {'sign': True, 'encrypt': False, 'sign_alg': 'RS256'}


def test_no_default_encrypt_algorithms():
    client_info = RegistrationResponse()
    srv_info = SrvInfo(conf, httplib=request)
    with pytest.raises(UnknownAlgorithm):
        get_sign_and_encrypt_algorithms(srv_info, client_info, 'id_token',
                                        sign=True, encrypt=True)

def test_get_sign_algorithm_2():
    client_info = RegistrationResponse(id_token_signed_response_alg='RS512')
    srv_info = SrvInfo(conf, httplib=request)
    algs = get_sign_and_encrypt_algorithms(srv_info, client_info, 'id_token',
                                           sign=True)
    # default signing alg
    assert algs == {'sign': True, 'encrypt': False, 'sign_alg': 'RS512'}


def test_get_sign_algorithm_3():
    client_info = RegistrationResponse()
    srv_info = SrvInfo(conf, httplib=request)
    srv_info.jwx_def["signing_alg"] = {'id_token':'RS384'}

    algs = get_sign_and_encrypt_algorithms(srv_info, client_info, 'id_token',
                                           sign=True)
    # default signing alg
    assert algs == {'sign': True, 'encrypt': False, 'sign_alg': 'RS384'}


def test_get_sign_algorithm_4():
    client_info = RegistrationResponse(id_token_signed_response_alg='RS512')
    srv_info = SrvInfo(conf, httplib=request)
    srv_info.jwx_def["signing_alg"] = {'id_token':'RS384'}

    algs = get_sign_and_encrypt_algorithms(srv_info, client_info, 'id_token',
                                           sign=True)
    # default signing alg
    assert algs == {'sign': True, 'encrypt': False, 'sign_alg': 'RS512'}
