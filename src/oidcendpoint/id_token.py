import logging
import uuid

from cryptojwt.jws.utils import left_hash
from cryptojwt.jwt import JWT
from oidcendpoint.session_management import unpack_db_key

from oidcendpoint.session_management import SessionInfo

from oidcendpoint import rndstr
from oidcendpoint.endpoint import construct_endpoint_info
from oidcendpoint.grant import Item
from oidcendpoint.session_management import db_key
from oidcendpoint.userinfo import ClaimsInterface

logger = logging.getLogger(__name__)

DEF_SIGN_ALG = {
    "id_token": "RS256",
    "userinfo": "RS256",
    "request_object": "RS256",
    "client_secret_jwt": "HS256",
    "private_key_jwt": "RS256",
}
DEF_LIFETIME = 300


def include_session_id(endpoint_context, client_id, where):
    """

    :param endpoint_context:
    :param client_id:
    :param dir: front or back
    :return:
    """
    _pinfo = endpoint_context.provider_info

    # Am the OP supposed to support {dir}-channel log out and if so can
    # it pass sid in logout token and ID Token
    for param in ["{}channel_logout_supported", "{}channel_logout_session_supported"]:
        try:
            _supported = _pinfo[param.format(where)]
        except KeyError:
            return False
        else:
            if not _supported:
                return False

    # Does the client support back-channel logout ?
    try:
        _val = endpoint_context.cdb[client_id]["{}channel_logout_uri".format(where)]
    except KeyError:
        return False

    return True


def get_sign_and_encrypt_algorithms(
        endpoint_context, client_info, payload_type, sign=False, encrypt=False
):
    args = {"sign": sign, "encrypt": encrypt}
    if sign:
        try:
            args["sign_alg"] = client_info[
                "{}_signed_response_alg".format(payload_type)
            ]
        except KeyError:  # Fall back to default
            try:
                args["sign_alg"] = endpoint_context.jwx_def["signing_alg"][payload_type]
            except KeyError:
                _def_sign_alg = DEF_SIGN_ALG[payload_type]
                _supported = endpoint_context.provider_info[
                    "{}_signing_alg_values_supported".format(payload_type)
                ]

                if _def_sign_alg in _supported:
                    args["sign_alg"] = _def_sign_alg
                else:
                    args["sign_alg"] = _supported[0]

    if encrypt:
        try:
            args["enc_alg"] = client_info["%s_encrypted_response_alg" % payload_type]
        except KeyError:
            try:
                args["enc_alg"] = endpoint_context.jwx_def["encryption_alg"][
                    payload_type
                ]
            except KeyError:
                _supported = endpoint_context.provider_info[
                    "{}_encryption_alg_values_supported".format(payload_type)
                ]
                args["enc_alg"] = _supported[0]

        try:
            args["enc_enc"] = client_info["%s_encrypted_response_enc" % payload_type]
        except KeyError:
            try:
                args["enc_enc"] = endpoint_context.jwx_def["encryption_enc"][
                    payload_type
                ]
            except KeyError:
                _supported = endpoint_context.provider_info[
                    "{}_encryption_enc_values_supported".format(payload_type)
                ]
                args["enc_enc"] = _supported[0]

    return args


class IDToken(object):
    default_capabilities = {
        "id_token_signing_alg_values_supported": None,
        "id_token_encryption_alg_values_supported": None,
        "id_token_encryption_enc_values_supported": None,
    }

    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.kwargs = kwargs
        self.scope_to_claims = None
        self.provider_info = construct_endpoint_info(
            self.default_capabilities, **kwargs
        )
        self.claims_interface = ClaimsInterface(endpoint_context, "id_token", **kwargs)

    def payload(
            self,
            session_id,
            alg="RS256",
            code=None,
            access_token=None,
            extra_claims=None,
    ):
        """

        :param session: Session information
        :param acr: Default Assurance/Authentication context class reference
        :param alg: Which signing algorithm to use for the IdToken
        :param code: Access grant
        :param access_token: Access Token
        :param user_info: If user info are to be part of the IdToken
        :param auth_time:
        :param lifetime: Life time of the ID Token
        :param extra_claims: extra claims to be added to the ID Token
        :return: IDToken instance
        """

        _mngr = self.endpoint_context.session_manager
        session_information = _mngr.get_session_info(session_id)
        _args = {"sub": session_information["client_session_info"]["sub"]}
        for claim, attr in {"authn_time": "auth_time", "acr": "acr"}.items():
            _val = session_information["user_session_info"]["authentication_event"].get(claim)
            if _val:
                _args[attr] = _val

        grant = _mngr.grants(session_id)[0]
        _claims_restriction = grant.claims.get(self.claims_interface.usage)
        user_info = self.claims_interface.get_user_claims(user_id=session_information["user_id"],
                                                          claims_restriction=_claims_restriction)

        if user_info:
            try:
                user_info = user_info.to_dict()
            except AttributeError:
                pass

            # Make sure that there are no name clashes
            for key in ["iss", "sub", "aud", "exp", "acr", "nonce", "auth_time"]:
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
            _args["at_hash"] = left_hash(access_token.encode("utf-8"), halg)

        authn_req = session_information["client_session_info"]["authorization_request"]
        if authn_req:
            try:
                _args["nonce"] = authn_req["nonce"]
            except KeyError:
                pass

        return _args

    def sign_encrypt(
            self,
            session_id,
            client_id,
            code=None,
            access_token=None,
            sign=True,
            encrypt=False,
            lifetime=None,
            extra_claims=None,
    ):
        """
        Signed and or encrypt a IDToken

        :param lifetime: How long the ID Token should be valid
        :param session_info: Session information
        :param client_id: Client ID
        :param code: Access grant
        :param access_token: Access Token
        :param sign: If the JWT should be signed
        :param encrypt: If the JWT should be encrypted
        :param extra_claims: Extra claims to be added to the ID Token
        :return: IDToken as a signed and/or encrypted JWT
        """

        _cntx = self.endpoint_context

        client_info = _cntx.cdb[client_id]
        alg_dict = get_sign_and_encrypt_algorithms(
            _cntx, client_info, "id_token", sign=sign, encrypt=encrypt
        )

        _payload = self.payload(
            session_id=session_id,
            alg=alg_dict["sign_alg"],
            code=code,
            access_token=access_token,
            extra_claims=extra_claims
        )

        if lifetime is None:
            lifetime = DEF_LIFETIME

        _jwt = JWT(
            _cntx.keyjar, iss=_cntx.issuer, lifetime=lifetime, **alg_dict
        )

        return _jwt.pack(_payload, recv=client_id)

    def make(self, session_id, **kwargs):
        _context = self.endpoint_context

        user_id, client_id, grant_id = unpack_db_key(session_id)

        # Should I add session ID. This is about Single Logout.
        if include_session_id(_context, client_id, "back") or include_session_id(
                _context, client_id, "front"):

            # Note that this session ID is not the session ID the session manager is using.
            # It must be possible to map from one to the other.
            logout_session_id = uuid.uuid4().get_hex()
            _item = SessionInfo()
            _item.set("user_id", user_id)
            _item.set("client_id", client_id)
            # Store the map
            _mngr = self.endpoint_context.session_manager
            _mngr.set([logout_session_id], _item)
            # add identifier to extra arguments
            xargs = {"sid": logout_session_id}
        else:
            xargs = {}

        lifetime = self.kwargs.get("lifetime")

        return self.sign_encrypt(
            session_id,
            client_id,
            sign=True,
            lifetime=lifetime,
            extra_claims=xargs,
            **kwargs
        )
