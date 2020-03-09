"""Implements RFC7662"""
import logging

from cryptojwt import JWT
from cryptojwt.jws.jws import factory
from oidcmsg import oauth2
from oidcmsg.time_util import utc_time_sans_frac

from oidcendpoint.endpoint import Endpoint

LOGGER = logging.getLogger(__name__)


def before(t1, t2, range):
    if t1 < (t2 - range):
        return True
    return False


def after(t1, t2, range):
    if t1 > (t2 + range):
        return True
    return False


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

    def do_jws(self, token):
        _jwt = JWT(key_jar=self.endpoint_context.keyjar)

        try:
            _jwt_info = _jwt.unpack(token)
        except Exception as err:
            return None

        return _jwt_info

    def do_access_token(self, token):
        try:
            _info = self.endpoint_context.sdb[token]
        except KeyError:
            return None

        _revoked = _info.get("revoked", False)
        if _revoked:
            return None

        _eat = _info.get("expires_at")
        if _eat < utc_time_sans_frac():
            return None

        if _info:  # Now what can be returned ?
            _ret = {
                "sub": _info["sub"],
                "client_id": _info["client_id"],
                "token_type": "bearer",
                "iss": self.endpoint_context.issuer
            }
            _authn = _info.get("authn_event")
            if _authn:
                _ret["authn_info"] = _authn["authn_info"]
                _ret["authn_time"] = _authn["authn_time"]

            _scope = _info.get("scope")
            if not _scope:
                _ret["scope"] = " ".join(_info["authn_req"]["scope"])

            return _ret
        else:
            return _info

    def process_request(self, request=None, **kwargs):
        """

        :param request: The authorization request as a dictionary
        :param kwargs:
        :return:
        """
        _introspect_request = self.request_cls(**request)
        if "error" in _introspect_request:
            return _introspect_request

        _token = _introspect_request["token"]
        _resp = self.response_cls(active=False)

        if factory(_token):
            _info = self.do_jws(_token)
            if _info is None:
                return {"response_args": _resp}
            _now = utc_time_sans_frac()

            # Time checks
            if "exp" in _info:
                if after(_now, _info["exp"], self.offset):
                    return {"response_args": _resp}
            if 'iat' in _info:
                if after(_info["iat"], _now, self.offset):
                    return {"response_args": _resp}
            if 'nbf' in _info:
                if before(_now, _info["nbf"], self.offset):
                    return {"response_args": _resp}
        else:
            # A non-jws access token
            _info = self.do_access_token(_token)
            if _info is None:
                return {"response_args": _resp}

        if not _info:
            return {"response_args": _resp}

        if "release" in self.kwargs:
            if "username" in self.kwargs["release"]:
                try:
                    _info["username"] = self.endpoint_context.userinfo.search(
                        sub=_info["sub"]
                    )
                except KeyError:
                    pass

        _resp.update(_info)
        _resp.weed()
        _resp["active"] = True

        return {"response_args": _resp}
