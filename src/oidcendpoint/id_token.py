import logging

from cryptojwt.jws.utils import left_hash
from cryptojwt.jwt import JWT
from oidcservice.exception import AccessDenied

from oidcendpoint.userinfo import collect_user_info
from oidcendpoint.userinfo import id_token_claims
from oidcendpoint.userinfo import userinfo_in_id_token_claims

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


DEF_SIGN_ALG = {
    "id_token": "RS256",
    "userinfo": "RS256",
    "request_object": "RS256",
    "client_secret_jwt": "HS256",
    "private_key_jwt": "RS256"
}


def get_sign_and_encrypt_algorithms(endpoint_context, client_info, payload_type,
                                    sign=False, encrypt=False):
    args = {'sign': sign, 'encrypt': encrypt}
    if sign:
        try:
            args['sign_alg'] = client_info[
                "{}_signed_response_alg".format(payload_type)]
        except KeyError:  # Fall back to default
            try:
                args['sign_alg'] = endpoint_context.jwx_def["signing_alg"][
                    payload_type]
            except KeyError:
                _def_sign_alg = DEF_SIGN_ALG[payload_type]
                _supported = endpoint_context.provider_info[
                    "{}_signing_alg_values_supported".format(payload_type)]

                if _def_sign_alg in _supported:
                    args['sign_alg'] = _def_sign_alg
                else:
                    args['sign_alg'] = _supported[0]

    if encrypt:
        try:
            args['enc_alg'] = client_info[
                "%s_encrypted_response_alg" % payload_type]
        except KeyError:
            try:
                args['enc_alg'] = endpoint_context.jwx_def["encryption_alg"][
                    payload_type]
            except KeyError:
                _supported = endpoint_context.provider_info[
                    "{}_encryption_alg_values_supported".format(payload_type)]
                args['enc_alg'] = _supported[0]

        try:
            args['enc_enc'] = client_info[
                "%s_encrypted_response_enc" % payload_type]
        except KeyError:
            try:
                args['enc_enc'] = endpoint_context.jwx_def["encryption_enc"][
                    payload_type]
            except KeyError:
                _supported = endpoint_context.provider_info[
                    "{}_encryption_enc_values_supported".format(payload_type)]
                args['enc_enc'] = _supported[0]

    return args


class IDToken(object):
    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.kwargs = kwargs

    def payload(self, session, loa="2", alg="RS256", code=None,
                access_token=None, user_info=None, auth_time=0,
                lifetime=300, extra_claims=None):
        """

        :param session: Session information
        :param loa: Level of Assurance/Authentication context
        :param alg: Which signing algorithm to use for the IdToken
        :param code: Access grant
        :param access_token: Access Token
        :param user_info: If user info are to be part of the IdToken
        :param auth_time:
        :param lifetime: Life time of the ID Token
        :param extra_claims: extra claims to be added to the ID Token
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
            _args["c_hash"] = left_hash(code.encode("utf-8"), halg)
        if access_token:
            _args["at_hash"] = left_hash(access_token.encode("utf-8"),
                                         halg)

        authn_req = session['authn_req']
        if authn_req:
            try:
                _args["nonce"] = authn_req["nonce"]
            except KeyError:
                pass

        return {'payload': _args, 'lifetime': lifetime}

    def sign_encrypt(self, session_info, client_id, code=None,
                     access_token=None, user_info=None, sign=True,
                     encrypt=False, extra_claims=None):
        """
        Signed and or encrypt a IDToken

        :param session_info: Session information
        :param client_id: Client ID
        :param code: Access grant
        :param access_token: Access Token
        :param user_info: User information
        :param sign: If the JWT should be signed
        :param encrypt: If the JWT should be encrypted
        :param extra_claims: Extra claims to be added to the ID Token
        :return: IDToken as a signed and/or encrypted JWT
        """

        _cntx = self.endpoint_context

        client_info = _cntx.cdb[client_id]
        alg_dict = get_sign_and_encrypt_algorithms(_cntx, client_info,
                                                   'id_token', sign=sign,
                                                   encrypt=encrypt)

        _authn_event = session_info['authn_event']

        _idt_info = self.payload(session_info, loa=_authn_event["authn_info"],
                                 alg=alg_dict['sign_alg'], code=code,
                                 access_token=access_token, user_info=user_info,
                                 auth_time=_authn_event["authn_time"],
                                 extra_claims=extra_claims)

        _jwt = JWT(_cntx.keyjar, iss=_cntx.issuer,
                   lifetime=_idt_info['lifetime'], **alg_dict)

        return _jwt.pack(_idt_info['payload'], recv=client_id)

    def make(self, req, sess_info, authn_req=None,
             user_claims=False, **kwargs):
        _context = self.endpoint_context
        _sdb = _context.sdb

        if authn_req:
            _cid = authn_req['client_id']
        else:
            _cid = req['client_id']

        _cinfo = _context.cdb[_cid]
        try:
            default_idtoken_claims = self.kwargs['default_claims']
        except KeyError:
            default_idtoken_claims = None

        userinfo = userinfo_in_id_token_claims(_context, sess_info,
                                               default_idtoken_claims)

        if user_claims:
            info = collect_user_info(_context, sess_info)
            if userinfo is None:
                userinfo = info
            else:
                userinfo.update(info)

        try:
            _client_id = req['client_id']
        except KeyError:
            if authn_req:
                _client_id = authn_req['client_id']
            else:
                raise ValueError('Expected authn request information')

        try:
            req_sid = _cinfo["frontchannel_logout_session_required"]
        except KeyError:
            try:
                req_sid = _cinfo["backchannel_logout_session_required"]
            except KeyError:
                req_sid = False

        if req_sid:
            xargs = {
                'sid': _context.sdb.get_sid_by_sub_and_client_id(
                    sess_info['sub'], _client_id)
            }
        else:
            xargs = {}

        return self.sign_encrypt(sess_info, _client_id,
                                 sign=True, user_info=userinfo,
                                 extra_claims=xargs, **kwargs)
