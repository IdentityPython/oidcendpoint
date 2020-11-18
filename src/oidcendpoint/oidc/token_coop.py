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
from oidcmsg.storage import importer

from oidcendpoint import sanitize
from oidcendpoint.cookie import new_cookie
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.exception import MultipleCodeUsage
from oidcendpoint.exception import ProcessError
from oidcendpoint.token_handler import AccessCodeUsed
from oidcendpoint.token_handler import ExpiredToken
from oidcendpoint.token_handler import UnknownToken
from oidcendpoint.userinfo import by_schema

logger = logging.getLogger(__name__)


class TokenEndpointHelper:
    def __init__(self, endpoint, config=None):
        self.endpoint = endpoint
        self.config = config

    def post_parse_request(self, request, client_id="", **kwargs):
        """Context specific parsing of the request.
        This is done after general request parsing and before processing
        the request.
        """
        raise NotImplementedError

    def process_request(self, req, **kwargs):
        """Acts on a process request."""
        raise NotImplementedError


class AccessToken(TokenEndpointHelper):
    def post_parse_request(self, request, client_id="", **kwargs):
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param authn: Authentication info, comes from HTTP header
        :returns:
        """

        request = AccessTokenRequest(**request.to_dict())

        error_cls = self._validate_state(request)
        if error_cls is not None:
            return error_cls

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = client_id

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request

    def _validate_state(self, request):
        if "state" not in request:
            return

        if "code" not in request:
            return self.endpoint.error_cls(
                error="invalid_request", error_description="Missing code"
            )

        try:
            sinfo = self.endpoint.endpoint_context.sdb[request["code"]]
        except (KeyError, UnknownToken):
            logger.error("Code not present in SessionDB")
            return self.endpoint.error_cls(
                error="invalid_grant", error_description="Invalid code"
            )
        except MultipleCodeUsage:
            return self.endpoint.error_cls(
                error="invalid_grant", error_description="Code is already used"
            )
        else:
            state = sinfo["authn_req"]["state"]

        if state != request["state"]:
            logger.error("State value mismatch")
            return self.endpoint.error_cls(error="invalid_request")

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

        # We can be sure that the code is there. The flow would have failed
        # earlier if it wasn't
        _info = _sdb[_access_code]

        _authn_req = _info["authn_req"]

        # assert that the code is valid
        if _context.sdb.is_session_revoked(_access_code):
            return self.endpoint.error_cls(
                error="invalid_grant", error_description="Session is revoked"
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
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _sdb.update_by_token(_access_code, id_token=_idtoken)
            _info = _sdb[_info["sid"]]

        return by_schema(AccessTokenResponse, **_info)


class RefreshToken(TokenEndpointHelper):
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
            request.verify(
                keyjar=self.endpoint.endpoint_context.keyjar, opponent_id=client_id
            )
        except (MissingRequiredAttribute, ValueError, MissingRequiredValue) as err:
            return self.endpoint.error_cls(
                error="invalid_request", error_description="%s" % err
            )

        if "client_id" not in request:  # Optional for refresh access token request
            request["client_id"] = client_id

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request

    def process_request(self, req, **kwargs):
        _sdb = self.endpoint.endpoint_context.sdb

        rtoken = req["refresh_token"]
        try:
            _info = _sdb.refresh_token(
                rtoken, new_refresh=self.endpoint.new_refresh_token
            )
        except ExpiredToken:
            return self.error_cls(
                error="invalid_request", error_description="Refresh token is expired"
            )

        return by_schema(AccessTokenResponse, **_info)


HELPER_BY_GRANT_TYPE = {
    "authorization_code": AccessToken,
    "refresh_token": RefreshToken,
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

    def __init__(self, endpoint_context, new_refresh_token=False, **kwargs):
        Endpoint.__init__(self, endpoint_context, **kwargs)
        self.post_parse_request.append(self._post_parse_request)
        if "client_authn_method" in kwargs:
            self.endpoint_info["token_endpoint_auth_methods_supported"] = kwargs[
                "client_authn_method"
            ]

        # self.allow_refresh = False
        self.new_refresh_token = new_refresh_token

        self.configure_grant_types(kwargs.get("grant_types_supported"))

    def configure_grant_types(self, grant_types_supported):
        if grant_types_supported is None:
            self.helper = {k: v(self) for k, v in HELPER_BY_GRANT_TYPE.items()}
            return

        self.helper = {}
        # TODO: do we want to allow any grant_type?
        for grant_type, grant_type_options in grant_types_supported.items():
            if (
                grant_type_options in (None, True)
                and grant_type in HELPER_BY_GRANT_TYPE
            ):
                self.helper[grant_type] = HELPER_BY_GRANT_TYPE[grant_type]
                continue
            elif grant_type_options is False:
                continue

            try:
                grant_class = grant_type_options["class"]
            except (KeyError, TypeError):
                raise ProcessError(
                    "Token Endpoint's grant types must be True, None or a dict with a"
                    " 'class' key."
                )
            _conf = grant_type_options.get("kwargs", {})

            if isinstance(grant_class, str):
                try:
                    grant_class = importer(grant_class)
                except (ValueError, AttributeError):
                    raise ProcessError(
                        f"Token Endpoint's grant type class {grant_class} can't"
                        " be imported."
                    )
            try:
                self.helper[grant_type] = grant_class(self, _conf)
            except Exception as e:
                raise ProcessError(f"Failed to initialize class {grant_class}: {e}")

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        sinfo = endpoint_context.sdb[token]
        return sinfo["authn_req"]["client_id"]

    def _post_parse_request(self, request, client_id="", **kwargs):
        _helper = self.helper.get(request["grant_type"])
        if _helper:
            return _helper.post_parse_request(request, client_id, **kwargs)
        else:
            return self.error_cls(
                error="invalid_request",
                error_description=f"Unsupported grant_type: {request['grant_type']}"
            )

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
                response_args = _helper.process_request(request, **kwargs)
            else:
                return self.error_cls(
                    error="invalid_request",
                    error_description=f"Unsupported grant_type: {request['grant_type']}"
                )
        except JWEException as err:
            return self.error_cls(error="invalid_request", error_description="%s" % err)

        if isinstance(response_args, ResponseMessage):
            return response_args

        _access_token = response_args["access_token"]
        _cookie = new_cookie(
            self.endpoint_context,
            sub=self.endpoint_context.sdb[_access_token]["sub"],
            cookie_name=self.endpoint_context.cookie_name["session"],
        )

        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        if _cookie:
            resp["cookie"] = _cookie
        return resp
