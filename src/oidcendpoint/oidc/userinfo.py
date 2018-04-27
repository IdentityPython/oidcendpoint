import json
import logging

from cryptojwt.exception import UnknownAlgorithm

from oidcmsg import oidc
from oidcmsg.jwt import JWT
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage

from oidcendpoint.endpoint import Endpoint
from oidcendpoint.exception import OidcEndpointError
from oidcendpoint.userinfo import collect_user_info
from oidcendpoint.util import get_sign_and_encrypt_algorithms
from oidcendpoint.util import OAUTH2_NOCACHE_HEADERS

logger = logging.getLogger(__name__)


class UserInfo(Endpoint):
    request_cls = Message
    response_cls = oidc.OpenIDSchema
    request_format = 'json'
    response_format = 'json'
    response_placement = 'body'
    endpoint_name = 'userinfo_endpoint'

    def do_response(self, response_args=None, request=None, **kwargs):
        _context = self.endpoint_context
        # Should I return a JSON or a JWT ?
        _cinfo = _context.cdb[kwargs['client_id']]

        # default is not to sign or encrypt
        sign_encrypt = {'sign': False, 'encrypt': False}
        if "userinfo_signed_response_alg" in _cinfo:
            sign_encrypt['sign'] = True
        if "userinfo_encrypted_response_alg" in _cinfo:
            sign_encrypt['encrypt'] = True

        if sign_encrypt['sign'] or sign_encrypt['encrypt']:
            try:
                jwt_args = get_sign_and_encrypt_algorithms(_context,
                                                           _cinfo,
                                                           'userinfo',
                                                           **sign_encrypt)
            except UnknownAlgorithm as err:
                raise OidcEndpointError('Configuration error: {}'.format(err))

            _jwt = JWT(_context.keyjar, **jwt_args)

            resp = _jwt.pack(payload=response_args)
            content_type = 'application/jwt'
        else:
            if isinstance(response_args, dict):
                resp = json.dumps(response_args)
            else:
                resp = response_args.to_json()
            content_type = 'application/json'

        http_headers = [('Content-type', content_type)]
        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        return {'response': resp, 'http_headers': http_headers}

    def process_request(self, request=None):
        _sdb = self.endpoint_context.sdb

        # should be an access token
        if not _sdb.is_token_valid(request['access_token']):
            return self.error_cls(error="invalid_token",
                                  error_description="Invalid Token")

        session = _sdb.read(request['access_token'])

        # Scope can translate to userinfo_claims
        info = collect_user_info(self.endpoint_context, session)

        return {'response_args': info, 'client_id': session['client_id']}

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
        auth_info = self.client_authentication({}, auth, **kwargs)
        if isinstance(auth_info, ResponseMessage):
            return auth_info
        else:
            request['client_id'] = auth_info['client_id']
            request['access_token'] = auth_info['token']

        return request
