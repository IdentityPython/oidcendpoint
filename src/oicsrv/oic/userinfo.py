import logging

from cryptojwt.exception import UnknownAlgorithm
from cryptojwt.jws import alg2keytype
from oicmsg import oic
from oicmsg.jwt import JWT
from oicmsg.message import Message
from oicmsg.oauth2 import ErrorResponse

from oicsrv.endpoint import Endpoint
from oicsrv.exception import OicSrvError
from oicsrv.userinfo import collect_user_info
from oicsrv.util import get_sign_and_encrypt_algorithms

logger = logging.getLogger(__name__)


class UserInfo(Endpoint):
    request_cls = Message
    response_cls = oic.OpenIDSchema
    request_format = 'json'
    response_format = 'json'
    response_placement = 'body'

    def process_request(self, srv_info, request=None):
        _sdb = srv_info.sdb

        # should be an access token
        if not _sdb.is_token_valid(request['access_token']):
            return self.error_cls(error="invalid_token",
                                  error_description="Invalid Token")

        session = _sdb.read(request['access_token'])

        # Scope can translate to userinfo_claims
        info = self.response_cls(**collect_user_info(srv_info, session))

        # Should I return a JSON or a JWT ?
        _cinfo = srv_info.cdb[session["client_id"]]

        sign_encrypt = {'sign': False, 'encrypt': False}
        if "userinfo_signed_response_alg" in _cinfo:
            sign_encrypt['sign'] = True
        if "userinfo_encrypted_response_alg" in _cinfo:
            sign_encrypt['encrypt'] = True

        try:
            jwt_args = get_sign_and_encrypt_algorithms(srv_info, _cinfo,
                                                       'userinfo',
                                                       **sign_encrypt)
        except UnknownAlgorithm as err:
            raise OicSrvError('Configuration error: {}'.format(err))

        _jwt = JWT(srv_info.keyjar, **jwt_args)

        if sign_encrypt['sign'] or sign_encrypt['encrypt']:
            jinfo = _jwt.pack(info)
            content_type = "application/jwt"
        else:
            jinfo = info.to_json()
            content_type = "application/json"

        return {'response':jinfo,
                'http_headers': [('Content-type', content_type)]}

    def parse_request(self, srv_info, request, auth=None, **kwargs):
        """

        :param request:
        :param srv_info:
        :param auth:
        :param kwargs:
        :return:
        """

        if not request:
            request = {}

        # Verify that the client is allowed to do this
        auth_info = self.client_authentication(srv_info, {}, auth, **kwargs)
        if isinstance(auth_info, ErrorResponse):
            return auth_info
        else:
            request['client_id'] = auth_info['client_id']
            request['access_token'] = auth_info['token']

        return request