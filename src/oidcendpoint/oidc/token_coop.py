import logging

from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from oidcmsg import oidc
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import MissingRequiredValue
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.oidc import TokenErrorResponse

from oidcendpoint import sanitize
from oidcendpoint.cookie import new_cookie
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.exception import ProcessError
from oidcendpoint.token_handler import AccessCodeUsed
from oidcendpoint.token_handler import ExpiredToken
from oidcendpoint.userinfo import by_schema

logger = logging.getLogger(__name__)


class EndpointHelper:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def process_request(self, req, **kwargs):
        raise NotImplemented()

    def post_parse_request(self, request, client_id="", **kwargs):
        raise NotImplemented()


class AccessToken(EndpointHelper):
    def process_request(self, req, **kwargs):
        _context = self.endpoint.endpoint_context
        _sdb = _context.sdb
        _log_debug = logger.debug

        try:
            _access_code = req["code"].replace(" ", "+")
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.endpoint.error_cls(
                error="invalid_request", error_description="Missing code"
            )

        # Session might not exist or _access_code malformed
        try:
            _info = _sdb[_access_code]
        except KeyError:
            return self.endpoint.error_cls(
                error="invalid_request", error_description="Code is invalid"
            )

        _authn_req = _info["authn_req"]

        # assert that the code is valid
        if _context.sdb.is_session_revoked(_access_code):
            return self.endpoint.error_cls(
                error="invalid_request", error_description="Session is revoked"
            )

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _authn_req:
            if req["redirect_uri"] != _authn_req["redirect_uri"]:
                return self.endpoint.error_cls(
                    error="invalid_request", error_description="redirect_uri mismatch"
                )

        _log_debug("All checks OK")

        issue_refresh = False
        if "issue_refresh" in kwargs:
            issue_refresh = kwargs["issue_refresh"]

        # offline_access the default if nothing is specified
        permissions = _info.get("permission", ["offline_access"])

        if "offline_access" in _authn_req["scope"] and "offline_access" in permissions:
            issue_refresh = True

        try:
            _info = _sdb.upgrade_to_token(_access_code, issue_refresh=issue_refresh)
        except AccessCodeUsed as err:
            logger.error("%s" % err)
            # Should revoke the token issued to this access code
            _sdb.revoke_all_tokens(_access_code)
            return self.endpoint.error_cls(
                error="access_denied", error_description="Access Code already used"
            )

        if "openid" in _authn_req["scope"]:
            try:
                _idtoken = _context.idtoken.make(req, _info, _authn_req)
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = TokenErrorResponse(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _sdb.update_by_token(_access_code, id_token=_idtoken)
            _info = _sdb[_info['sid']]

        return by_schema(AccessTokenResponse, **_info)

    def post_parse_request(self, request, client_id="", **kwargs):
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param authn: Authentication info, comes from HTTP header
        :returns:
        """

        request = AccessTokenRequest(**request.to_dict())

        if "state" in request:
            try:
                sinfo = self.endpoint.endpoint_context.sdb[request["code"]]
            except KeyError:
                logger.error("Code not present in SessionDB")
                return self.endpoint.error_cls(error="unauthorized_client")
            else:
                state = sinfo["authn_req"]["state"]

            if state != request["state"]:
                logger.error("State value mismatch")
                return self.endpoint.error_cls(error="unauthorized_client")

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = client_id

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request


class RefreshToken(EndpointHelper):
    def process_request(self, req, **kwargs):
        _sdb = self.endpoint.endpoint_context.sdb

        rtoken = req["refresh_token"]
        try:
            _info = _sdb.refresh_token(rtoken)
        except ExpiredToken:
            return self.endpoint.error_cls(
                error="invalid_request", error_description="Refresh token is expired"
            )

        return by_schema(AccessTokenResponse, **_info)

    def post_parse_request(self, request, client_id="", **kwargs):
        """
        This is where clients come to refresh their access tokens

        :param request: The request
        :param authn: Authentication info, comes from HTTP header
        :returns:
        """

        request = RefreshAccessTokenRequest(**request.to_dict())

        # verify that the request message is correct
        try:
            request.verify(keyjar=self.endpoint.endpoint_context.keyjar)
        except (MissingRequiredAttribute, ValueError, MissingRequiredValue) as err:
            return self.endpoint.error_cls(error="invalid_request", error_description="%s" % err)

        try:
            keyjar = self.endpoint.endpoint_context.keyjar
        except AttributeError:
            keyjar = ""

        request.verify(keyjar=keyjar, opponent_id=client_id)

        if "client_id" not in request:  # Optional for refresh access token request
            request["client_id"] = client_id

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request


HELPER_BY_GRANT_TYPE = {
    "authorization_code": AccessToken,
    "refresh_token": RefreshToken
}


class TokenCoop(Endpoint):
    request_cls = oidc.Message
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
        # self.allow_refresh = False
        self.helper = HELPER_BY_GRANT_TYPE

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        sinfo = endpoint_context.sdb[token]
        return sinfo["authn_req"]["client_id"]

    def _post_parse_request(self, request, client_id="", **kwargs):
        _helper = self.helper.get(request["grant_type"])
        if _helper:
            return _helper(self).post_parse_request(request, client_id, **kwargs)
        else:
            raise ProcessError("No support for grant_type: {}", request["grant_type"])

    def process_request(self, request=None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        if isinstance(request, self.error_cls):
            return request
        try:
            _helper = self.helper.get(request["grant_type"])
            if _helper:
                response_args = _helper(self).process_request(request, **kwargs)
            else:
                return self.error_cls(
                    error="invalid_request",
                    error_description="Unsupported grant_type {}".format(request["grant_type"])
                )
        except JWEException as err:
            return self.error_cls(error="invalid_request", error_description="%s" % err)

        if isinstance(response_args, ResponseMessage):
            return response_args

        _access_token = response_args["access_token"]
        _cookie = new_cookie(
            self.endpoint_context, sub=self.endpoint_context.sdb[_access_token]["sub"]
        )

        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        if _cookie:
            resp["cookie"] = _cookie
        return resp
