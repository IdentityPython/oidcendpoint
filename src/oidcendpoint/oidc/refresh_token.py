import logging

from oidcmsg import oidc
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.oidc import TokenErrorResponse
from oidcmsg.time_util import time_sans_frac

from oidcendpoint import sanitize
from oidcendpoint.client_authn import verify_client
from oidcendpoint.cookie import new_cookie
from oidcendpoint.endpoint import Endpoint

logger = logging.getLogger(__name__)


class RefreshAccessToken(Endpoint):
    request_cls = oidc.RefreshAccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_cls = TokenErrorResponse
    request_format = "json"
    request_placement = "body"
    response_format = "json"
    response_placement = "body"
    endpoint_name = "token_endpoint"
    name = "refresh_token"

    def __init__(self, endpoint_context, **kwargs):
        Endpoint.__init__(self, endpoint_context, **kwargs)
        self.post_parse_request.append(self._post_parse_request)

    def _refresh_access_token(self, req, **kwargs):
        _mngr = self.endpoint_context.session_manager

        if req["grant_type"] != "refresh_token":
            return self.error_cls(
                error="invalid_request", error_description="Wrong grant_type"
            )

        rtoken = req["refresh_token"]
        _session_info = _mngr.get_session_info_by_token(rtoken)
        grant, token = _mngr.find_grant(_session_info["session_id"], rtoken)
        if token.is_active is False:
            return self.error_cls(
                error="invalid_request", error_description="Refresh token inactive"
            )

        access_token = grant.mint_token(
            'access_token',
            value=_mngr.token_handler["access_token"](
                _session_info["session_id"],
                client_id=_session_info["client_id"],
                aud=grant.resources,
                user_claims=None,
                scope=grant.scope,
                sub=_session_info["client_session_info"]['sub']
            ),
            expires_at=time_sans_frac() + 900,  # 15 minutes from now
            based_on=rtoken  # Means the token (tok) was used to mint this token
        )

        return {"access_token": access_token, "token_type": "Bearer",
                "expires_in": 900, "scope": grant.scope}

    def client_authentication(self, request, auth=None, **kwargs):
        """
        Deal with client authentication

        :param request: The refresh access token request
        :param auth: Client authentication information
        :param kwargs: Extra keyword arguments
        :return: dictionary containing client id, client authentication method
            and possibly access token.
        """
        try:
            auth_info = verify_client(self.endpoint_context, request, auth)
            msg = ""
        except Exception as err:
            msg = "Failed to verify client due to: {}".format(err)
            logger.error(msg)
            return self.error_cls(error="unauthorized_client", error_description=msg)
        else:
            if "client_id" not in auth_info:
                logger.error("No client_id, authentication failed")
                return self.error_cls(
                    error="unauthorized_client", error_description="unknown client"
                )

        return auth_info

    def _post_parse_request(self, request, client_id="", **kwargs):
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

        if "client_id" not in request:  # Optional for refresh access token request
            request["client_id"] = client_id

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request

    def process_request(self, request=None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        response_args = self._refresh_access_token(request, **kwargs)

        if isinstance(response_args, ResponseMessage):
            return response_args


        _token = request["refresh_token"].replace(" ", "+")
        _session_info = self.endpoint_context.session_manager.get_session_info_by_token(_token)
        _cookie = new_cookie(
            self.endpoint_context,
            sub=_session_info["client_session_info"]["sub"],
            cookie_name=self.endpoint_context.cookie_name["session"],
        )
        _headers = [("Content-type", "application/json")]
        resp = {"response_args": response_args, "http_headers": _headers}
        if _cookie:
            resp["cookie"] = _cookie
        return resp
