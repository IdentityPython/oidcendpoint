import json
import logging

from cryptojwt.exception import MissingValue
from cryptojwt.jwt import JWT
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg import oidc
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage

from oidcendpoint.endpoint import Endpoint
from oidcendpoint.session_management import unpack_db_key
from oidcendpoint.token_handler import UnknownToken
# from oidcendpoint.userinfo import collect_user_info
from oidcendpoint.userinfo import ClaimsInterface
from oidcendpoint.util import OAUTH2_NOCACHE_HEADERS

logger = logging.getLogger(__name__)


class UserInfo(Endpoint):
    request_cls = Message
    response_cls = oidc.OpenIDSchema
    request_format = "json"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "userinfo_endpoint"
    name = "userinfo"
    default_capabilities = {
        "claim_types_supported": ["normal", "aggregated", "distributed"],
        "userinfo_signing_alg_values_supported": None,
        "userinfo_encryption_alg_values_supported": None,
        "userinfo_encryption_enc_values_supported": None,
        "client_authn_method": ["bearer_header"],
    }

    def __init__(self, endpoint_context, **kwargs):
        Endpoint.__init__(self, endpoint_context, **kwargs)
        # Add the issuer ID as an allowed JWT target
        self.allowed_targets.append("")
        self.claims_interface = ClaimsInterface(endpoint_context, "userinfo", **kwargs)

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        _info = endpoint_context.session_manager.token_handler.info(token)
        sinfo = self.endpoint_context.session_manager[_info["sid"]]
        return sinfo["authorization_request"]["client_id"]

    def do_response(self, response_args=None, request=None, client_id="", **kwargs):

        if "error" in kwargs and kwargs["error"]:
            return Endpoint.do_response(self, response_args, request, **kwargs)

        _context = self.endpoint_context
        if not client_id:
            raise MissingValue("client_id")

        # Should I return a JSON or a JWT ?
        _cinfo = _context.cdb[client_id]

        # default is not to sign or encrypt
        try:
            sign_alg = _cinfo["userinfo_signed_response_alg"]
            sign = True
        except KeyError:
            sign_alg = ""
            sign = False

        try:
            enc_enc = _cinfo["userinfo_encrypted_response_enc"]
            enc_alg = _cinfo["userinfo_encrypted_response_alg"]
            encrypt = True
        except KeyError:
            encrypt = False
            enc_alg = enc_enc = ""

        if encrypt or sign:
            _jwt = JWT(
                self.endpoint_context.keyjar,
                iss=self.endpoint_context.issuer,
                sign=sign,
                sign_alg=sign_alg,
                encrypt=encrypt,
                enc_enc=enc_enc,
                enc_alg=enc_alg,
            )

            resp = _jwt.pack(response_args, recv=client_id)
            content_type = "application/jwt"
        else:
            if isinstance(response_args, dict):
                resp = json.dumps(response_args)
            else:
                resp = response_args.to_json()
            content_type = "application/json"

        http_headers = [("Content-type", content_type)]
        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        return {"response": resp, "http_headers": http_headers}

    def process_request(self, request=None, **kwargs):
        _mngr = self.endpoint_context.session_manager
        _info = _mngr.token_handler.info(request["access_token"])
        grant, token = _mngr.find_grant(_info['sid'], request["access_token"])
        # should be an access token
        if token.is_active() is False:
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )
        _user_id, _client_id = unpack_db_key(_info['sid'])
        _cs_info = _mngr.get([_user_id, _client_id])
        _us_info = _mngr.get([_user_id])
        allowed = True
        # if the authenticate is still active or offline_access is granted.
        if _us_info["authentication_event"]["valid_until"] > utc_time_sans_frac():
            pass
        else:
            logger.debug("authentication not valid: {} > {}".format(
                _us_info["authentication_event"]["valid_until"], utc_time_sans_frac()
            ))
            allowed = False

            # This has to be made more fine grained.
            # if "offline_access" in session["authn_req"]["scope"]:
            #     pass

        if allowed:
            # Scope can translate to userinfo_claims
            _restrictions = grant.claims.get("userinfo")
            info = self.claims_interface.get_user_claims(
                user_id=_user_id, claims_restriction=_restrictions)
        else:
            info = {
                "error": "invalid_request",
                "error_description": "Access not granted",
            }

        return {"response_args": info, "client_id": _client_id}

    def parse_request(self, request, auth=None, **kwargs):
        """

        :param request:
        :param auth:
        :param kwargs:
        :return:
        """

        if not request:
            request = {}

        # Verify that the client is allowed to do this
        try:
            auth_info = self.client_authentication(
                request, auth, endpoint="userinfo", **kwargs
            )
        except (ValueError, UnknownToken) as e:
            return self.error_cls(
                error="invalid_token", error_description=e.args[0]
            )

        if isinstance(auth_info, ResponseMessage):
            return auth_info
        else:
            request["client_id"] = auth_info["client_id"]
            request["access_token"] = auth_info["token"]

        return request
