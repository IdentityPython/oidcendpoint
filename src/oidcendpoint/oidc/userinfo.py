import json
import logging

from cryptojwt.exception import MissingValue
from cryptojwt.jwt import JWT
from oidcmsg import oidc
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import time_sans_frac

from oidcendpoint.endpoint import Endpoint
from oidcendpoint.userinfo import collect_user_info
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
        self.scope_to_claims = None
        if "client_authn_method" not in kwargs:
            self.client_authn_method = self.default_capabilities["client_authn_method"]
        # Add the issuer ID as an allowed JWT target
        self.allowed_targets.append("")

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        sinfo = self.endpoint_context.sdb[token]
        return sinfo["authn_req"]["client_id"]

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
        _sdb = self.endpoint_context.sdb

        # should be an access token
        if not _sdb.is_token_valid(request["access_token"]):
            return self.error_cls(
                error="invalid_token", error_description="Invalid Token"
            )

        session = _sdb.read(request["access_token"])

        allowed = True
        # if the authenticate is still active or offline_access is granted.
        if session["authn_event"]["valid_until"] > time_sans_frac():
            pass
        else:
            if "offline_access" in session["authn_req"]["scope"]:
                pass
            else:
                allowed = False

        if allowed:
            # Scope can translate to userinfo_claims
            info = collect_user_info(self.endpoint_context, session)
        else:
            info = {
                "error": "invalid_request",
                "error_description": "Offline access not granted",
            }

        return {"response_args": info, "client_id": session["authn_req"]["client_id"]}

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
        auth_info = self.client_authentication(request, auth, endpoint="userinfo", **kwargs)
        if isinstance(auth_info, ResponseMessage):
            return auth_info
        else:
            request["client_id"] = auth_info["client_id"]
            request["access_token"] = auth_info["token"]

        return request
