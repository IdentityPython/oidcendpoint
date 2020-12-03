"""Implements RFC7662"""
import logging

from oidcmsg import oauth2

from oidcendpoint.endpoint import Endpoint
from oidcendpoint.token.exception import UnknownToken

LOGGER = logging.getLogger(__name__)


class Introspection(Endpoint):
    """Implements RFC 7662"""

    request_cls = oauth2.TokenIntrospectionRequest
    response_cls = oauth2.TokenIntrospectionResponse
    request_format = "urlencoded"
    response_format = "json"
    endpoint_name = "introspection_endpoint"
    name = "introspection"

    def __init__(self, **kwargs):
        Endpoint.__init__(self, **kwargs)
        self.offset = kwargs.get("offset", 0)

    def _introspect(self, token, session_info):
        # Make sure that the token is an access_token or a refresh_token
        if token.type not in ["access_token", "refresh_token"]:
            return None

        if not token.is_active():
            return None

        scope = token.scope
        if not scope:
            scope = session_info["grant"].scope
        aud = token.resources
        if not aud:
            aud = session_info["grant"].resources

        _csi = session_info["client_session_info"]
        ret = {
            "active": True,
            "scope": " ".join(scope),
            "client_id": session_info["client_id"],
            "token_type": token.type,
            "exp": token.expires_at,
            "iat": token.issued_at,
            "sub": _csi["sub"],
            "iss": self.endpoint_context.issuer
        }
        if aud:
            ret["aud"] = aud

        return ret

    def process_request(self, request=None, **kwargs):
        """

        :param request: The authorization request as a dictionary
        :param kwargs:
        :return:
        """
        _introspect_request = self.request_cls(**request)
        if "error" in _introspect_request:
            return _introspect_request

        request_token = _introspect_request["token"]
        _resp = self.response_cls(active=False)

        try:
            _session_info = self.endpoint_context.session_manager.get_session_info_by_token(
                request_token)
        except UnknownToken:
            return {"response_args": _resp}

        _token = self.endpoint_context.session_manager.find_token(_session_info["session_id"],
                                                                  request_token)

        _info = self._introspect(_token, _session_info)
        if _info is None:
            return {"response_args": _resp}

        if "release" in self.kwargs:
            if "username" in self.kwargs["release"]:
                try:
                    _info["username"] = _session_info["user_id"]
                except KeyError:
                    pass

        _resp.update(_info)
        _resp.weed()

        _claims_restriction = _session_info["grant"].claims.get("introspection")
        if _claims_restriction:
            user_info = self.endpoint_context.claims_interface.get_user_claims(
                _session_info["user_id"], _claims_restriction)
            if user_info:
                _resp.update(user_info)

        _resp["active"] = True

        return {"response_args": _resp}
