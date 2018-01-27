import logging

from cryptojwt import jws
from cryptojwt.jwe import JWE
from cryptojwt.jwk import SYMKey
from cryptojwt.jws import alg2keytype
from oiccli import sanitize
from oiccli.exception import AccessDenied
from oiccli.oic.service import PROVIDER_DEFAULT
from oicmsg import time_util
from oicmsg.oic import IdToken

from oicsrv.userinfo import id_token_claims

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


def make_id_token(srv_info, session, loa="2", issuer="",
                  alg="RS256", code=None, access_token=None,
                  user_info=None, auth_time=0, exp=None, extra_claims=None):
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
    # defaults
    if exp is None:
        inawhile = {"days": 1}
    else:
        inawhile = exp
    # Handle the idtoken_claims
    extra = {}
    itc = id_token_claims(session)
    if itc.keys():
        try:
            inawhile = {"seconds": itc["max_age"]}
        except KeyError:
            pass
        for key, val in itc.items():
            if key == "auth_time":
                extra["auth_time"] = auth_time
            elif key == "acr":
                # ["2","http://id.incommon.org/assurance/bronze"]
                extra["acr"] = verify_acr_level(val, loa)
    else:
        if auth_time:
            extra["auth_time"] = auth_time
        if loa:
            extra["acr"] = loa

    if not user_info:
        _args = {}
    else:
        try:
            _args = user_info.to_dict()
        except AttributeError:
            _args = user_info

    # Make sure that there are no name clashes
    for key in ["iss", "sub", "aud", "exp", "acr", "nonce",
                "auth_time"]:
        try:
            del _args[key]
        except KeyError:
            pass

    halg = "HS%s" % alg[-3:]

    if extra_claims is not None:
        _args.update(extra_claims)
    if code:
        _args["c_hash"] = jws.left_hash(code.encode("utf-8"), halg)
    if access_token:
        _args["at_hash"] = jws.left_hash(access_token.encode("utf-8"),
                                         halg)

    idt = IdToken(iss=issuer, sub=session["sub"],
                  aud=session["client_id"],
                  exp=time_util.epoch_in_a_while(**inawhile), acr=loa,
                  iat=time_util.utc_time_sans_frac(),
                  **_args)

    for key, val in extra.items():
        idt[key] = val

    if "nonce" in session:
        idt["nonce"] = session["nonce"]

    return idt


def id_token_as_signed_jwt(srv_info, session, loa="2", alg="", code=None,
                           access_token=None, user_info=None, auth_time=0,
                           exp=None, extra_claims=None, **kwargs):
    if alg == "":
        alg = srv_info.jwx_def["signing_alg"]["id_token"]

    if alg:
        logger.debug("Signing alg: %s [%s]" % (alg, alg2keytype(alg)))
    else:
        alg = "none"

    _idt = make_id_token(srv_info, session, loa, srv_info.issuer, alg, code,
                         access_token, user_info, auth_time,
                         exp, extra_claims)

    try:
        ckey = kwargs['keys']
    except KeyError:
        try:
            _keyjar = kwargs['keyjar']
        except KeyError:
            _keyjar = srv_info.keyjar

        logger.debug("id_token: %s" % sanitize(_idt.to_dict()))
        # My signing key if its RS*, can use client secret if HS*
        if alg.startswith("HS"):
            logger.debug("client_id: %s" % session["client_id"])
            ckey = _keyjar.get_signing_key(alg2keytype(alg),
                                           session["client_id"])
            if not ckey:  # create a new key
                _secret = srv_info.cdb[session["client_id"]]["client_secret"]
                ckey = [SYMKey(key=_secret)]
        else:
            if "" in srv_info.keyjar:
                ckey = _keyjar.get_signing_key(alg2keytype(alg), "",
                                               alg=alg)
            else:
                ckey = None

    _signed_jwt = _idt.to_jwt(key=ckey, algorithm=alg)

    return _signed_jwt


def encrypt(srv_info, payload, client_info, cid, val_type="id_token", cty=""):
    """
    Handles the encryption of a payload.
    Shouldn't get here unless there are encrypt parameters in client info

    :param payload: The information to be encrypted
    :param client_info: Client information
    :param cid: Client id
    :return: The encrypted information as a JWT
    """

    try:
        alg = client_info["%s_encrypted_response_alg" % val_type]
    except KeyError:
        logger.warning('{} NOT defined means no encryption').format(
            val_type)
        return payload
    else:
        try:
            enc = client_info["%s_encrypted_response_enc" % val_type]
        except KeyError as err:  # if not defined-> A128CBC-HS256 (default)
            logger.warning("undefined parameter: %s" % err)
            logger.info("using default")
            enc = 'A128CBC-HS256'

    logger.debug("alg=%s, enc=%s, val_type=%s" % (alg, enc, val_type))
    keys = srv_info.keyjar.get_encrypt_key(owner=cid)
    if cid not in srv_info.keyjar:
        # Weird, but try to recuperate
        msg = "Lost keys for %s trying to recuperate!"
        logger.warning(msg, cid)

        srv_info.keyjar.issuer_keys[cid] = []
        srv_info.keyjar.add(cid, client_info["jwks_uri"])

    kwargs = {"alg": alg, "enc": enc}
    if cty:
        kwargs["cty"] = cty

    # use the clients public key for encryption
    _jwe = JWE(payload, **kwargs)
    return _jwe.encrypt(keys, context="public")


def sign_encrypt_id_token(srv_info, sinfo, client_info, areq,
                          code=None, access_token=None, user_info=None):
    """
    Signed and or encrypt a IDToken

    :param sinfo: Session information
    :param client_info: Client information
    :param areq: The request
    :param code: Access grant
    :param access_token: Access Token
    :param user_info: User information
    :return: IDToken instance
    """

    try:
        alg = client_info["id_token_signed_response_alg"]
    except KeyError:
        try:
            alg = srv_info.jwx_def["signing_alg"]["id_token"]
        except KeyError:
            alg = PROVIDER_DEFAULT["id_token_signed_response_alg"]
        else:
            if not alg:
                alg = PROVIDER_DEFAULT["id_token_signed_response_alg"]

    _authn_event = sinfo["authn_event"]
    id_token = id_token_as_signed_jwt(srv_info,
                                      sinfo, loa=_authn_event["authn_info"],
                                      alg=alg, code=code,
                                      access_token=access_token,
                                      user_info=user_info,
                                      auth_time=_authn_event["authn_time"])

    # Then encrypt
    if "id_token_encrypted_response_alg" in client_info:
        id_token = encrypt(id_token, client_info, areq["client_id"],
                           "id_token", "JWT")

    return id_token
