import logging
from http.cookies import SimpleCookie

from cryptojwt.exception import UnknownAlgorithm

logger = logging.getLogger(__name__)

OAUTH2_NOCACHE_HEADERS = [
    ('Pragma', 'no-cache'),
    ('Cache-Control', 'no-store'),
]


def make_headers(endpoint_context, user, **kwargs):
    headers = []
    try:
        _kaka = kwargs["cookie"]
    except KeyError:
        pass
    else:
        if _kaka:
            if isinstance(_kaka, dict):
                for name, val in _kaka.items():
                    _c = SimpleCookie()
                    _c[name] = val
                    _x = _c.output()
                    headers.append(tuple(_x.split(": ", 1)))
            else:
                _c = SimpleCookie()
                _c.load(_kaka)
                for x in _c.output().split('\r\n'):
                    headers.append(tuple(x.split(": ", 1)))

            if endpoint_context.cookie_name not in _kaka:  # Don't overwrite
                header = endpoint_context.cookie_func(user, typ="sso",
                                              ttl=endpoint_context.sso_ttl)
                if header:
                    headers.append(header)
        else:
            header = endpoint_context.cookie_func(user, typ="sso",
                                          ttl=endpoint_context.sso_ttl)
            if header:
                headers.append(header)
    return headers


DEF_SIGN_ALG = {"id_token": "RS256",
                "userinfo": "RS256",
                "request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "RS256"}


def get_sign_and_encrypt_algorithms(endpoint_context, client_info, payload_type,
                                    sign=False, encrypt=False):
    args = {'sign': sign, 'encrypt': encrypt}
    if sign:
        try:
            args['sign_alg'] = client_info[
                "{}_signed_response_alg".format(payload_type)]
        except KeyError:  # Fall back to default
            try:
                args['sign_alg'] = endpoint_context.jwx_def["signing_alg"][payload_type]
            except KeyError:
                args['sign_alg'] = DEF_SIGN_ALG[payload_type]

    if encrypt:
        try:
            args['enc_alg'] = client_info[
                "%s_encrypted_response_alg" % payload_type]
        except KeyError:
            try:
                args['enc_alg'] = endpoint_context.jwx_def["encryption_alg"][
                    payload_type]
            except KeyError:
                raise UnknownAlgorithm(
                    "Don't know which encryption algorithm to use")

        try:
            args['enc_enc'] = client_info[
                "%s_encrypted_response_enc" % payload_type]
        except KeyError:
            try:
                args['enc_enc'] = endpoint_context.jwx_def["encryption_enc"][
                    payload_type]
            except KeyError:
                raise UnknownAlgorithm(
                    "Don't know which encryption algorithm to use")

    return args


def build_endpoints(conf, endpoint_context, client_authn_method, issuer):
    """
    conf typically contains::

        'provider_config': {
            'path': '.well-known/openid-configuration',
            'class': ProviderConfiguration,
            'kwargs': {}
        },

    :param conf:
    :param endpoint_context:
    :param client_authn_method:
    :param issuer:
    :return:
    """

    if issuer.endswith('/'):
        _url = issuer[:-1]
    else:
        _url = issuer

    endpoint = {}
    for name, spec in conf.items():
        try:
            kwargs = spec['kwargs']
        except KeyError:
            kwargs = {}

        _instance = spec['class'](endpoint_context=endpoint_context, **kwargs)
        _instance.endpoint_path = spec['path'].format(_url)

        try:
            _client_authn_method = kwargs['client_authn_method']
        except KeyError:
            _instance.client_auth_method = client_authn_method
        else:
            _instance.client_auth_method = _client_authn_method

        endpoint[name] = _instance

    return endpoint


