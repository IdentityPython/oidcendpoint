import json
import logging

from oidcmsg import oidc
from cryptojwt.jwt import JWT
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import time_sans_frac

from oidcendpoint.endpoint import Endpoint
from oidcendpoint.userinfo import collect_user_info
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

        if 'error' in kwargs and kwargs['error']:
            return Endpoint.do_response(self, response_args, request, **kwargs)

        _context = self.endpoint_context
        # Should I return a JSON or a JWT ?
        _cinfo = _context.cdb[kwargs['client_id']]

        # default is not to sign or encrypt
        try:
            sign_alg = _cinfo['userinfo_signed_response_alg']
            sign = True
        except KeyError:
            sign_alg = ''
            sign = False

        try:
            enc_enc = _cinfo['userinfo_encrypted_response_enc']
            enc_alg = _cinfo['userinfo_encrypted_response_alg']
            encrypt = True
        except KeyError:
            encrypt = False
            enc_alg = enc_enc = ''

        if encrypt or sign:
            _jwt = JWT(self.endpoint_context.keyjar,
                       iss=self.endpoint_context.issuer,
                       sign=sign, sign_alg=sign_alg, encrypt=encrypt,
                       enc_enc=enc_enc, enc_alg=enc_alg)

            resp = _jwt.pack(response_args['response'],
                             recv=kwargs['client_id'])
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

    def process_request(self, request=None, **kwargs):
        _sdb = self.endpoint_context.sdb

        # should be an access token
        if not _sdb.is_token_valid(request['access_token']):
            return self.error_cls(error="invalid_token",
                                  error_description="Invalid Token")

        session = _sdb.read(request['access_token'])

        allowed = True
        # if the authenticate is still active or offline_access is granted.
        if session['authn_event']['valid_until'] > time_sans_frac():
            pass
        else:
            if 'offline_access' in session['authn_req']['scope']:
                pass
            else:
                allowed = False

        if allowed:
            # Scope can translate to userinfo_claims
            info = collect_user_info(self.endpoint_context, session)
        else:
            info = {'error': 'invalid_request',
                    'error_description': 'Offline access not granted'}

        return {'response_args': info,
                'client_id': session['authn_req']['client_id']}

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
        auth_info = self.client_authentication(request, auth, **kwargs)
        if isinstance(auth_info, ResponseMessage):
            return auth_info
        else:
            request['client_id'] = auth_info['client_id']
            request['access_token'] = auth_info['token']

        return request
