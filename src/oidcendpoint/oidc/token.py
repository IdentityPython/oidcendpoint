import logging

from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from oidcmsg import oidc
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import TokenErrorResponse
from oidcmsg.time_util import time_sans_frac

from oidcendpoint import sanitize
from oidcendpoint.cookie import new_cookie
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.session_management import unpack_db_key

logger = logging.getLogger(__name__)


class AccessToken(Endpoint):
    request_cls = oidc.AccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_cls = TokenErrorResponse
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "token_endpoint"
    name = "token"
    default_capabilities = {"token_endpoint_auth_signing_alg_values_supported": None}

    def __init__(self, endpoint_context, **kwargs):
        Endpoint.__init__(self, endpoint_context, **kwargs)
        self.post_parse_request.append(self._post_parse_request)
        if "client_authn_method" in kwargs:
            self.endpoint_info["token_endpoint_auth_methods_supported"] = kwargs[
                "client_authn_method"
            ]

    def _access_token(self, req, **kwargs):
        _context = self.endpoint_context
        _mngr = _context.session_manager
        _log_debug = logger.debug

        if req["grant_type"] != "authorization_code":
            return self.error_cls(
                error="invalid_request", error_description="Unknown grant_type"
            )

        try:
            _access_code = req["code"].replace(" ", "+")
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.error_cls(
                error="invalid_request", error_description="Missing code"
            )

        _session_info = _mngr.get_session_info_by_token(_access_code)
        grant, code = _mngr.find_grant(_session_info["session_id"], _access_code)

        # assert that the code is valid
        if code.is_active() is False:
            return self.error_cls(
                error="invalid_grant", error_description="Code is invalid"
            )

        _authn_req = _session_info["client_session_info"]["authorization_request"]

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _authn_req:
            if req["redirect_uri"] != _authn_req["redirect_uri"]:
                return self.error_cls(
                    error="invalid_request", error_description="redirect_uri mismatch"
                )

        _log_debug("All checks OK")

        issue_refresh = False
        if "issue_refresh" in kwargs:
            issue_refresh = kwargs["issue_refresh"]
        else:
            if "offline_access" in grant.scope:
                issue_refresh = True

        token = grant.mint_token(
            "access_token",
            value=_mngr.token_handler["access_token"](
                _session_info["session_id"],
                client_id=_session_info["client_id"],
                aud=grant.resources,
                user_claims=None,
                scope=grant.scope,
                sub=_session_info["client_session_info"]['sub']
            ),
            expires_at=time_sans_frac() + 900,  # 15 minutes from now
            based_on=code
        )

        _response = {
            "access_token": token.value,
            "token_type": "Bearer",
            "expires_in": 900,
            "scope": grant.scope,
            "state": _authn_req["state"]
        }

        if issue_refresh:
            refresh_token = grant.mint_token(
                "refresh_token",
                value=_mngr.token_handler["refresh_token"](
                    _session_info["session_id"],
                    client_id=_session_info["client_id"],
                    aud=grant.resources,
                    user_claims=None,
                    scope=grant.scope,
                    sub=_session_info["client_session_info"]['sub']
                ),
                based_on=code
            )
            _response["refresh_token"] = refresh_token.value

        code.register_usage()

        if "openid" in _authn_req["scope"]:
            try:
                _idtoken = _context.idtoken.make(_session_info["user_id"],
                                                 _session_info["client_id"])
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _response["id_token"] = _idtoken

        return _response

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        sinfo = endpoint_context.sdb[token]
        return sinfo["authn_req"]["client_id"]

    def _post_parse_request(self, request, client_id="", **kwargs):
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param authn: Authentication info, comes from HTTP header
        :returns:
        """

        _mngr = self.endpoint_context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(request["code"])
        except KeyError:
            logger.error("Access Code invalid")
            return self.error_cls(error="invalid_grant")

        grant, code = _mngr.find_grant(_session_info["session_id"], request["code"])
        _auth_req = _session_info["client_session_info"]["authorization_request"]
        if code.is_active():
            state = _auth_req["state"]
        else:
            logger.error("Access Code inactive")
            # Remove any access tokens issued
            if code.max_usage_reached():
                _mngr.revoke_token(_session_info["session_id"],
                                   code.value, recursive=True)
            return self.error_cls(error="invalid_grant")

        if "state" in request:
            # verify that state in this request is the same as the one in the
            # authorization request
            if state != request["state"]:
                logger.error("State value mismatch")
                return self.error_cls(error="invalid_request")

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = _auth_req["client_id"]

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request

    def process_request(self, request=None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        if isinstance(request, self.error_cls):
            return request
        try:
            response_args = self._access_token(request, **kwargs)
        except JWEException as err:
            return self.error_cls(error="invalid_request", error_description="%s" % err)

        if isinstance(response_args, ResponseMessage):
            return response_args

        _mngr = self.endpoint_context.session_manager
        _tinfo = _mngr.token_handler.info(request["code"])
        _cs_info = _mngr[_tinfo["sid"]]

        _cookie = new_cookie(
            self.endpoint_context,
            sub=_cs_info["sub"],
            cookie_name=self.endpoint_context.cookie_name["session"],
        )
        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        if _cookie:
            resp["cookie"] = _cookie
        return resp
