import logging

from cryptojwt import jws

from oidcmsg.jwt import JWT

from oidcservice.exception import AccessDenied

from oidcendpoint.userinfo import id_token_claims
from oidcendpoint.util import get_sign_and_encrypt_algorithms

logger = logging.getLogger(__name__)

ACR_LISTS = [
    ["0", "1", "2", "3", "4"],
]


def verify_acr_level(req, level):
    if req is None:
        return level
    elif "values" in req:
        for _r in req["values"]:
            for alist in ACR_LISTS:
                try:
                    if alist.index(_r) <= alist.index(level):
                        return level
                except ValueError:
                    pass
    else:  # Required or Optional
        return level

    raise AccessDenied("", req)


def id_token_payload(session, loa="2", alg="RS256", code=None,
                     access_token=None, user_info=None, auth_time=0,
                     lifetime=300, extra_claims=None):
    """

    :param session: Session information
    :param loa: Level of Assurance/Authentication context
    :param issuer: My identifier
    :param alg: Which signing algorithm to use for the IdToken
    :param code: Access grant
    :param access_token: Access Token
    :param user_info: If user info are to be part of the IdToken
    :return: IDToken instance
    """

    _args = {'sub': session['sub']}

    # Handle the idtoken_claims
    itc = id_token_claims(session)

    if itc.keys():
        try:
            lifetime = itc["max_age"]
        except KeyError:
            pass

        for key, val in itc.items():
            if key == "auth_time":
                _args["auth_time"] = auth_time
            elif key == "acr":
                # ["2","http://id.incommon.org/assurance/bronze"]
                _args["acr"] = verify_acr_level(val, loa)
    else:
        if auth_time:
            _args["auth_time"] = auth_time
        if loa:
            _args["acr"] = loa

    if user_info:
        try:
            user_info = user_info.to_dict()
        except AttributeError:
            pass

        # Make sure that there are no name clashes
        for key in ["iss", "sub", "aud", "exp", "acr", "nonce",
                    "auth_time"]:
            try:
                del user_info[key]
            except KeyError:
                pass

        _args.update(user_info)

    if extra_claims is not None:
        _args.update(extra_claims)

    # Left hashes of code and/or access_token
    halg = "HS%s" % alg[-3:]
    if code:
        _args["c_hash"] = jws.left_hash(code.encode("utf-8"), halg)
    if access_token:
        _args["at_hash"] = jws.left_hash(access_token.encode("utf-8"),
                                         halg)

    try:
        _args["nonce"] = session["nonce"]
    except KeyError:
        pass

    return {'payload': _args, 'lifetime': lifetime}


def sign_encrypt_id_token(endpoint_context, session_info, client_id, code=None,
                          access_token=None, user_info=None, sign=True,
                          encrypt=False):
    """
    Signed and or encrypt a IDToken

    :param endpoint_context: Server Information
    :param session_info: Session information
    :param client_id: Client ID
    :param code: Access grant
    :param access_token: Access Token
    :param user_info: User information
    :param sign: If the JWT should be signed
    :param encrypt: If the JWT should be encrypted
    :return: IDToken as a signed and/or encrypted JWT
    """

    client_info = endpoint_context.cdb[client_id]
    alg_dict = get_sign_and_encrypt_algorithms(endpoint_context, client_info,
                                               'id_token', sign=sign,
                                               encrypt=encrypt)

    _authn_event = session_info["authn_event"]

    _idt_info = id_token_payload(session_info, loa=_authn_event["authn_info"],
                                 alg = alg_dict['sign_alg'], code=code,
                                 access_token=access_token, user_info=user_info,
                                 auth_time=_authn_event["authn_time"])

    _jwt = JWT(endpoint_context.keyjar, iss=endpoint_context.issuer,
               lifetime=_idt_info['lifetime'], **alg_dict)

    return _jwt.pack(_idt_info['payload'], recv=client_id)
