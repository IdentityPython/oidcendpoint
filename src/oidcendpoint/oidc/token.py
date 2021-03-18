import logging
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from cryptojwt.exception import JWKESTException
from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg import oidc
from oidcmsg.message import Message
from oidcmsg.exception import MissingRequiredValue, MissingRequiredAttribute
from oidcmsg.oauth2 import TokenExchangeRequest, ResponseMessage, TokenExchangeResponse
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.oidc import TokenErrorResponse
from oidcmsg.time_util import time_sans_frac

from oidcendpoint import sanitize
from oidcendpoint.cookie import new_cookie
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.exception import ProcessError
from oidcendpoint.session import unpack_session_key, MintingNotAllowed
from oidcendpoint.session.grant import AuthorizationCode
from oidcendpoint.session.grant import Grant
from oidcendpoint.session.grant import RefreshToken
from oidcendpoint.session.token import AccessToken, Token as sessionToken
from oidcendpoint.token.exception import UnknownToken
from oidcendpoint.util import importer

logger = logging.getLogger(__name__)


class TokenEndpointHelper(object):
    def __init__(self, endpoint, config=None):
        self.endpoint = endpoint
        self.config = config
        self.endpoint_context = endpoint.endpoint_context
        self.error_cls = self.endpoint.error_cls

    def post_parse_request(self, request: Union[Message, dict],
                           client_id: Optional[str] = "",
                           **kwargs):
        """Context specific parsing of the request.
        This is done after general request parsing and before processing
        the request.
        """
        raise NotImplementedError

    def process_request(self, req: Union[Message, dict], **kwargs):
        """Acts on a process request."""
        raise NotImplementedError

    def _mint_token(self, token_type: str, grant: Grant, session_id: str,
                    based_on: Optional[sessionToken] = None) -> sessionToken:
        _mngr = self.endpoint_context.session_manager
        usage_rules = grant.usage_rules.get(token_type)
        if usage_rules:
            _exp_in = usage_rules.get("expires_in")
        else:
            _exp_in = 0

        token = grant.mint_token(
            session_id,
            endpoint_context=self.endpoint_context,
            token_type=token_type,
            token_handler=_mngr.token_handler["access_token"],
            based_on=based_on,
            usage_rules=usage_rules
        )

        if _exp_in:
            if isinstance(_exp_in, str):
                _exp_in = int(_exp_in)

            if _exp_in:
                token.expires_at = time_sans_frac() + _exp_in

        self.endpoint_context.session_manager.set(
            unpack_session_key(session_id), grant)

        return token


class AccessTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        """

        :param req:
        :param kwargs:
        :return:
        """
        _context = self.endpoint.endpoint_context

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

        _session_info = _mngr.get_session_info_by_token(_access_code, grant=True)
        grant = _session_info["grant"]

        code = _mngr.find_token(_session_info["session_id"], _access_code)
        _authn_req = grant.authorization_request

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

        _response = {
            "token_type": "Bearer",
            "scope": grant.scope,
            "state": _authn_req["state"]
        }

        token = self._mint_token(token_type="access_token",
                                 grant=grant,
                                 session_id=_session_info["session_id"],
                                 based_on=code)
        _response["access_token"] = token.value
        _response["expires_in"] = token.expires_at - utc_time_sans_frac()

        if issue_refresh:
            refresh_token = self._mint_token(token_type="refresh_token",
                                             grant=grant,
                                             session_id=_session_info["session_id"],
                                             based_on=code)
            _response["refresh_token"] = refresh_token.value

        code.register_usage()

        # since the grant content has changed
        _mngr[_session_info["session_id"]] = grant

        if "openid" in _authn_req["scope"]:
            try:
                _idtoken = _context.idtoken.make(_session_info["session_id"])
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _response["id_token"] = _idtoken

        return _response

    def post_parse_request(self, request: Union[Message, dict],
                           client_id: Optional[str] = "",
                           **kwargs):
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param client_id: Client identifier
        :returns:
        """

        _mngr = self.endpoint_context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(request["code"],
                                                            grant=True)
        except KeyError:
            logger.error("Access Code invalid")
            return self.error_cls(error="invalid_grant",
                                  error_description="Unknown code")

        code = _mngr.find_token(_session_info["session_id"], request["code"])
        if not isinstance(code, AuthorizationCode):
            return self.error_cls(
                error="invalid_request", error_description="Wrong token type"
            )

        if code.is_active() is False:
            return self.error_cls(
                error="invalid_request", error_description="Code inactive"
            )

        _auth_req = _session_info["grant"].authorization_request

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = _auth_req["client_id"]

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request


class RefreshTokenHelper(TokenEndpointHelper):
    def process_request(self, req: Union[Message, dict], **kwargs):
        _mngr = self.endpoint_context.session_manager

        if req["grant_type"] != "refresh_token":
            return self.error_cls(
                error="invalid_request", error_description="Wrong grant_type"
            )

        token_value = req["refresh_token"]
        _session_info = _mngr.get_session_info_by_token(token_value, grant=True)
        token = _mngr.find_token(_session_info["session_id"], token_value)

        _grant = _session_info["grant"]
        access_token = self._mint_token(token_type="access_token",
                                        grant=_grant,
                                        session_id=_session_info["session_id"],
                                        based_on=token)

        _resp = {
            "access_token": access_token.value,
            "token_type": "Bearer",
            "scope": _grant.scope
        }

        if access_token.expires_at:
            _resp["expires_in"] = access_token.expires_at - utc_time_sans_frac()

        _mints = token.usage_rules.get("supports_minting")
        if "refresh_token" in _mints:
            refresh_token = self._mint_token(token_type="refresh_token",
                                             grant=_grant,
                                             session_id=_session_info["session_id"],
                                             based_on=token)
            refresh_token.usage_rules = token.usage_rules.copy()
            _resp["refresh_token"] = refresh_token.value

        if "id_token" in _mints:
            try:
                _idtoken = self.endpoint_context.idtoken.make(_session_info["session_id"])
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = self.error_cls(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token",
                )
                return resp

            _resp["id_token"] = _idtoken

        return _resp

    def post_parse_request(self, request: Union[Message, dict],
                           client_id: Optional[str] = "",
                           **kwargs):
        """
        This is where clients come to refresh their access tokens

        :param request: The request
        :param authn: Authentication info, comes from HTTP header
        :returns:
        """

        request = RefreshAccessTokenRequest(**request.to_dict())

        try:
            keyjar = self.endpoint_context.keyjar
        except AttributeError:
            keyjar = ""

        request.verify(keyjar=keyjar, opponent_id=client_id)

        _mngr = self.endpoint_context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(request["refresh_token"])
        except KeyError:
            logger.error("Access Code invalid")
            return self.error_cls(error="invalid_grant")

        token = _mngr.find_token(_session_info["session_id"], request["refresh_token"])

        if not isinstance(token, RefreshToken):
            return self.error_cls(
                error="invalid_request", error_description="Wrong token type"
            )

        if token.is_active() is False:
            return self.error_cls(
                error="invalid_request", error_description="Refresh token inactive"
            )

        return request


class TokenExchangeHelper(TokenEndpointHelper):
    """Implements Token Exchange a.k.a. RFC8693"""

    def __init__(self, endpoint, config=None):
        TokenEndpointHelper.__init__(self, endpoint=endpoint, config=config)

        # TODO: should we even have a policy for the simple use cases?
        if config is None:
            self.policy = {}
        else:
            self.policy = config.get('policy', {})

        # TODO: Make this a part of the policy. Note the distinction between
        # requested_token_type, subject_token_type, actor_token_type, issued_token_type
        self.token_types_allowed = [
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:jwt",
            # "urn:ietf:params:oauth:token-type:id_token",
            # "urn:ietf:params:oauth:token-type:refresh_token",
        ]

    def post_parse_request(self, request, client_id="", **kwargs):
        request = TokenExchangeRequest(**request.to_dict())

        # if "client_id" not in request:
        #     request["client_id"] = client_id

        keyjar = getattr(self.endpoint_context, "keyjar", "")

        try:
            request.verify(keyjar=keyjar, opponent_id=client_id)
        except (
            MissingRequiredAttribute,
            ValueError,
            MissingRequiredValue,
            JWKESTException,
        ) as err:
            return self.endpoint.error_cls(
                error="invalid_request", error_description="%s" % err
            )


        error = self.check_for_errors(request=request)
        if error is not None:
            return error

        _mngr = self.endpoint_context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["subject_token"], grant=True
            )
        except (KeyError, UnknownToken):
            logger.error("Subject token invalid.")
            return self.error_cls(
                error="invalid_request",
                error_description="Subject token invalid"
            )

        token = _mngr.find_token(_session_info["session_id"], request["subject_token"])

        if not isinstance(token, AccessToken):
            return self.error_cls(
                error="invalid_request", error_description="Wrong token type"
            )

        if token.is_active() is False:
            return self.error_cls(
                error="invalid_request", error_description="Subject token inactive"
            )

        return request

    def check_for_errors(self, request):
        context = self.endpoint.endpoint_context
        if "resource" in request:
            iss = urlparse(context.issuer)
            if any(
                urlparse(res).netloc != iss.netloc for res in request["resource"]
            ):
                return TokenErrorResponse(
                    error="invalid_target", error_description="Unknown resource"
                )

        if "audience" in request:
            if any(
                aud != context.issuer for aud in request["audience"]
            ):
                return TokenErrorResponse(
                    error="invalid_target", error_description="Unknown audience"
                )

        # TODO: if requested type is jwt make sure our tokens are jwt
        if (
            "requested_token_type" in request
            and request["requested_token_type"] not in self.token_types_allowed
        ):
            return TokenErrorResponse(
                error="invalid_target",
                error_description="Unsupported requested token type"
            )

        if "actor_token" in request or "actor_token_type" in request:
            return TokenErrorResponse(
                error="invalid_request", error_description="Actor token not supported"
            )

        # TODO: also check if the (valid) subject_token matches subject_token_type
        if request["subject_token_type"] not in self.token_types_allowed:
            return TokenErrorResponse(
                error="invalid_request",
                error_description="Unsupported subject token type",
            )

    def token_exchange_response(self, token):
        response_args = {
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": token.type,
            "access_token": token.value,
            "scope": token.scope,
            "expires_in": token.usage_rules["expires_in"]
        }
        return TokenExchangeResponse(**response_args)

    def process_request(self, request, **kwargs):
        # TODO: should we even have a policy for the simple use cases?
        # client_policy = self.policy.get(req["client_id"]) or self.policy.get("default")
        # if not client_policy:
        #     logger.error(
        #         "TokenExchange policy for client {req['client_id']} or default missing."
        #     )
        #     return TokenErrorResponse(
        #         error="invalid_request", error_description="Not allowed"
        #     )
        _mngr = self.endpoint_context.session_manager
        try:
            _session_info = _mngr.get_session_info_by_token(
                request["subject_token"],
                grant=True,
            )
        except KeyError:
            logger.error("Subject token invalid.")
            return self.error_cls(
                error="invalid_grant",
                error_description="Subject token invalid",
            )

        token = _mngr.find_token(_session_info["session_id"], request["subject_token"])
        grant = _session_info["grant"]

        try:
            new_token = grant.mint_token(
                session_id=_session_info["session_id"],
                endpoint_context=self.endpoint_context,
                token_type='access_token',
                token_handler=_mngr.token_handler["access_token"],
                based_on=token,
                resources=request.get("resource"),
                scope=request.get("scope"),
            )
        except MintingNotAllowed:
            logger.error("Minting not allowed for 'access_token'")
            return self.error_cls(
                error="invalid_grant",
                error_description="Token Exchange not allowed with that token",
            )

        return self.token_exchange_response(token=new_token)


HELPER_BY_GRANT_TYPE = {
    "authorization_code": AccessTokenHelper,
    "refresh_token": RefreshTokenHelper,
    "urn:ietf:params:oauth:grant-type:token-exchange": TokenExchangeHelper,
}


class Token(Endpoint):
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
        self.allow_refresh = False
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

    def _post_parse_request(self, request: Union[Message, dict],
                            client_id: Optional[str] = "", **kwargs):
        _helper = self.helper.get(request["grant_type"])
        if _helper:
            return _helper.post_parse_request(request, client_id, **kwargs)
        else:
            return self.error_cls(
                error="invalid_request",
                error_description=f"Unsupported grant_type: {request['grant_type']}"
            )

    def process_request(self, request: Optional[Union[Message, dict]] = None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        if isinstance(request, self.error_cls):
            return request

        if request is None:
            return self.error_cls(error="invalid_request")

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
        _session_info = self.endpoint_context.session_manager.get_session_info_by_token(
            _access_token, grant=True)

        _cookie = new_cookie(
            self.endpoint_context,
            sub=_session_info["grant"].sub,
            cookie_name=self.endpoint_context.cookie_name["session"],
        )

        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        if _cookie:
            resp["cookie"] = _cookie
        return resp
