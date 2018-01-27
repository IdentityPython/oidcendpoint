import logging
from http.cookies import SimpleCookie

from cryptojwt.exception import UnknownAlgorithm

logger = logging.getLogger(__name__)

OAUTH2_NOCACHE_HEADERS = [
    ('Pragma', 'no-cache'),
    ('Cache-Control', 'no-store'),
]


def make_headers(srv_info, user, **kwargs):
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

            if srv_info.cookie_name not in _kaka:  # Don't overwrite
                header = srv_info.cookie_func(user, typ="sso",
                                              ttl=srv_info.sso_ttl)
                if header:
                    headers.append(header)
        else:
            header = srv_info.cookie_func(user, typ="sso",
                                          ttl=srv_info.sso_ttl)
            if header:
                headers.append(header)
    return headers


DEF_SIGN_ALG = {"id_token": "RS256",
                "userinfo": "RS256",
                "request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "RS256"}


def get_sign_and_encrypt_algorithms(srv_info, client_info, payload_type,
                                    sign=False, encrypt=False):
    args = {'sign': sign, 'encrypt': encrypt}
    if sign:
        try:
            args['sign_alg'] = client_info[
                "{}_signed_response_alg".format(payload_type)]
        except KeyError:  # Fall back to default
            try:
                args['sign_alg'] = srv_info.jwx_def["signing_alg"][payload_type]
            except KeyError:
                args['sign_alg'] = DEF_SIGN_ALG[payload_type]

    if encrypt:
        try:
            args['enc_alg'] = client_info[
                "%s_encrypted_response_alg" % payload_type]
        except KeyError:
            try:
                args['enc_alg'] = srv_info.jwx_def["encryption_alg"][
                    payload_type]
            except KeyError:
                raise UnknownAlgorithm(
                    "Don't know which encryption algorithm to use")

        try:
            args['enc_enc'] = client_info[
                "%s_encrypted_response_enc" % payload_type]
        except KeyError:
            try:
                args['enc_enc'] = srv_info.jwx_def["encryption_enc"][
                    payload_type]
            except KeyError:
                raise UnknownAlgorithm(
                    "Don't know which encryption algorithm to use")

    return args
