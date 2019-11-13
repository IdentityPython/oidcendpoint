"""Implements RFC7662"""
import logging

from cryptojwt import JWT
from oidcmsg import oauth2
from oidcmsg.time_util import utc_time_sans_frac

from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint import Endpoint

LOGGER = logging.getLogger(__name__)


class Introspection(Endpoint):
    request_cls = oauth2.TokenIntrospectionRequest
    response_cls = oauth2.TokenIntrospectionResponse
    request_format = 'urlencoded'
    response_format = 'json'
    endpoint_name = 'introspection'

    def do_response(self, response_args=None, request=None, **kwargs):
        """Construct an Introspection response.

        :param response_args:
        :param request:
        :param kwargs: request arguments
        :return: Response information
        """
        info = {
            'response': response_args.to_json(),
            'http_headers': [('Content-type', 'application/json')]
        }

        return info

    def client_authentication(self, request, auth=None, **kwargs):
        """
        Deal with client authentication

        :param request: The introspection request
        :param auth: Client authentication information
        :param kwargs: Extra keyword arguments
        :return: dictionary containing client id, client authentication method.
        """

        try:
            auth_info = verify_client(self.endpoint_context, request, auth)
        except Exception as err:
            msg = "Failed to verify client due to: {}".format(err)
            LOGGER.error(msg)
            return self.error_cls(error="unauthorized_client",
                                  error_description=msg)
        else:
            if 'client_id' not in auth_info:
                LOGGER.error('No client_id, authentication failed')
                return self.error_cls(error="unauthorized_client",
                                      error_description='unknown client')

        return auth_info

    def process_request(self, request_info=None, **kwargs):
        """

        :param request_info: The authorization request as a dictionary
        :param kwargs:
        :return:
        """
        _introspect_request = self.request_cls(**request_info)

        _jwt = JWT(key_jar=self.endpoint_context.keyjar)

        try:
            _jwt_info = _jwt.unpack(_introspect_request['token'])
        except Exception:
            return {'response': {'active': False}}

        # expired ?
        if 'exp' in _jwt_info:
            now = utc_time_sans_frac()
            if _jwt_info['exp'] < now:
                return {'response': {'active': False}}

        if 'release' in self.kwargs:
            if 'username' in self.kwargs['release']:
                try:
                    _jwt_info['username'] = self.endpoint_context.userinfo.search(sub=_jwt_info['sub'])
                except KeyError:
                    return {'response': {'active': False}}

        _resp = self.response_cls(**_jwt_info)
        _resp.weed()
        _resp['active'] = True

        return {'response_args': _resp}
