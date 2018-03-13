import pytest

from cryptojwt.exception import UnknownAlgorithm

from oidcmsg.oidc import RegistrationResponse

from oidcendpoint.oidc.authorization import Authorization
from oidcendpoint.oidc.provider_config import ProviderConfiguration
from oidcendpoint.oidc.registration import Registration
from oidcendpoint.oidc.token import AccessToken
from oidcendpoint.oidc.userinfo import UserInfo
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD

from oidcendpoint.util import get_sign_and_encrypt_algorithms

conf = {
    "issuer": "https://example.com/",
    "password": "mycket hemligt",
    "token_expires_in": 600,
    "grant_expires_in": 300,
    "refresh_token_expires_in": 86400,
    "verify_ssl": False,
    "capabilities": {},
    "jwks_uri": 'https://example.com/jwks.json',
    'endpoint': {
        'provider_config': {
            'path': '{}/.well-known/openid-configuration',
            'class': ProviderConfiguration,
            'kwargs': {}
        },
        'registration_endpoint': {
            'path': '{}/registration',
            'class': Registration,
            'kwargs': {}
        },
        'authorization_endpoint': {
            'path': '{}/authorization',
            'class': Authorization,
            'kwargs': {}
        },
        'token_endpoint': {
            'path': '{}/token',
            'class': AccessToken,
            'kwargs': {}
        },
        'userinfo_endpoint': {
            'path': '{}/userinfo',
            'class': UserInfo,
            'kwargs': {'db_file': 'users.json'}
        }
    },
    'authentication': [
        {
            'acr': INTERNETPROTOCOLPASSWORD,
            'name': 'NoAuthn',
            'kwargs': {'user': 'diana'}
        }
    ],
    'template_dir': 'template'
}


def test_get_sign_algorithm():
    client_info = RegistrationResponse()
    endpoint_context = EndpointContext(conf)
    algs = get_sign_and_encrypt_algorithms(endpoint_context, client_info,
                                           'id_token',
                                           sign=True)
    # default signing alg
    assert algs == {'sign': True, 'encrypt': False, 'sign_alg': 'RS256'}


def test_no_default_encrypt_algorithms():
    client_info = RegistrationResponse()
    endpoint_context = EndpointContext(conf)
    with pytest.raises(UnknownAlgorithm):
        get_sign_and_encrypt_algorithms(endpoint_context, client_info,
                                        'id_token',
                                        sign=True, encrypt=True)


def test_get_sign_algorithm_2():
    client_info = RegistrationResponse(id_token_signed_response_alg='RS512')
    endpoint_context = EndpointContext(conf)
    algs = get_sign_and_encrypt_algorithms(endpoint_context, client_info,
                                           'id_token',
                                           sign=True)
    # default signing alg
    assert algs == {'sign': True, 'encrypt': False, 'sign_alg': 'RS512'}


def test_get_sign_algorithm_3():
    client_info = RegistrationResponse()
    endpoint_context = EndpointContext(conf)
    endpoint_context.jwx_def["signing_alg"] = {'id_token': 'RS384'}

    algs = get_sign_and_encrypt_algorithms(endpoint_context, client_info,
                                           'id_token',
                                           sign=True)
    # default signing alg
    assert algs == {'sign': True, 'encrypt': False, 'sign_alg': 'RS384'}


def test_get_sign_algorithm_4():
    client_info = RegistrationResponse(id_token_signed_response_alg='RS512')
    endpoint_context = EndpointContext(conf)
    endpoint_context.jwx_def["signing_alg"] = {'id_token': 'RS384'}

    algs = get_sign_and_encrypt_algorithms(endpoint_context, client_info,
                                           'id_token',
                                           sign=True)
    # default signing alg
    assert algs == {'sign': True, 'encrypt': False, 'sign_alg': 'RS512'}
