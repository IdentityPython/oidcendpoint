"""Implements RFC7662"""
import logging

from cryptojwt import JWT
from oidcmsg import oauth2
from oidcmsg.time_util import utc_time_sans_frac

from oidcendpoint.endpoint import Endpoint

LOGGER = logging.getLogger(__name__)


class Introspection(Endpoint):
    """Implements RFC 7662"""

    request_cls = oauth2.TokenIntrospectionRequest
    response_cls = oauth2.TokenIntrospectionResponse
    request_format = "urlencoded"
    response_format = "json"
    endpoint_name = "introspection"
    name = "introspection"

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        """
        Will try to match tokens against information in the session DB.

        :param endpoint_context:
        :param token:
        :param request:
        :return: client_id if there was a match
        """
        sinfo = endpoint_context.sdb[token]
        return sinfo["authn_req"]["client_id"]

    def process_request(self, request=None, **kwargs):
        """

        :param request: The authorization request as a dictionary
        :param kwargs:
        :return:
        """
        _introspect_request = self.request_cls(**request)
        if "error" in _introspect_request:
            return _introspect_request

        _resp = self.response_cls(active=False)

        _jwt = JWT(key_jar=self.endpoint_context.keyjar)

        try:
            _jwt_info = _jwt.unpack(_introspect_request["token"])
        except Exception:
            return {"response_args": _resp}

        # expired ?
        if "exp" in _jwt_info:
            now = utc_time_sans_frac()
            if _jwt_info["exp"] < now:
                return {"response_args": _resp}

        if "release" in self.kwargs:
            if "username" in self.kwargs["release"]:
                try:
                    _jwt_info["username"] = self.endpoint_context.userinfo.search(
                        sub=_jwt_info["sub"]
                    )
                except KeyError:
                    return {"response_args": _resp}

        _resp.update(_jwt_info)
        _resp.weed()
        _resp["active"] = True

        return {"response_args": _resp}
