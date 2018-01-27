import logging
from http.cookies import SimpleCookie

from cryptojwt.exception import UnknownAlgorithm
from cryptojwt.jwe import JWE
from oicmsg.jwt import JWT

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


# def encrypt(srv_info, payload, client_info, cid, payload_type="id_token"):
#     """
#     Handles the encryption of a payload.
#     Shouldn't get here unless there are encrypt parameters in client info
#
#     :param payload_type: The payload message type (id_token, userinfo, ...)
#     :param payload: The information to be encrypted
#     :param client_info: Client information
#     :param cid: Client id
#     :return: The encrypted information as a JWT
#     """
#
#     try:
#         alg = client_info["%s_encrypted_response_alg" % payload_type]
#     except KeyError:
#         logger.warning('{} NOT defined, means no encryption').format(
#             payload_type)
#         return payload
#     else:
#         try:
#             enc = client_info["%s_encrypted_response_enc" % payload_type]
#         except KeyError as err:  # if not defined-> A128CBC-HS256 (default)
#             logger.warning("undefined parameter: %s" % err)
#             logger.info("using default")
#             enc = 'A128CBC-HS256'
#
#     logger.debug(
#         "Encrypting info with alg={}, enc={}, payload_type={}".format(
#             alg, enc, payload_type))
#
#     _jwe = JWT(srv_info.keyjar, sign=False, encrypt=True,
#                enc_enc=enc, enc_alg=alg)
#
#     # use the clients public key for encryption
#     return _jwe.pack(payload)

# "signing_alg", "encryption_alg", "encryption_enc"


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
                raise UnknownAlgorithm(
                    "Don't know which signing algorithm to use")

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
