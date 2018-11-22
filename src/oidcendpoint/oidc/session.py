import json
import logging
from urllib.parse import urlencode, splitquery

from cryptojwt import b64d, as_unicode
from cryptojwt.jws.exception import JWSException
from jwkest import as_bytes
from oidcmsg.exception import InvalidRequest

from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc.session import EndSessionRequest

from oidcendpoint import URL_ENCODED
from oidcendpoint.client_authn import UnknownOrNoAuthnMethod
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.util import OAUTH2_NOCACHE_HEADERS

logger = logging.getLogger(__name__)


class Session(Endpoint):
    request_cls = EndSessionRequest
    response_cls = Message
    request_format = 'urlencoded'
    response_format = 'urlencoded'
    response_placement = 'url'
    endpoint_name = 'end_session_endpoint'

    def do_response(self, response_args=None, request=None, **kwargs):
        """
        Gather response information

        :param response_args: Things that should be in the response
        :param request: The original request
        :param kwargs: Extra keyword arguments
        :return: A dictionary with 2 keys 'response' and ' http_headers'
        """
        if 'error' in kwargs and kwargs['error']:
            return Endpoint.do_response(self, response_args, request, **kwargs)

        http_headers = [('Content-type', URL_ENCODED)]
        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        return {'response': response_args, 'http_headers': http_headers}

    def process_request(self, request=None, cookie=None, **kwargs):
        """
        Perform user logout

        :param request:
        :param cookie:
        :param kwargs:
        :return:
        """
        _sdb = self.endpoint_context.sdb

        try:
            part = self.endpoint_context.cookie_dealer.get_cookie_value(
                cookie, cookie_name='oidc_op')
        except IndexError:
            raise InvalidRequest('Cookie error')

        if part:
            # value is a base64 encoded JSON document
            _cookie_info = json.loads(as_unicode(b64d(as_bytes(part[0]))))
            _sid = _cookie_info['sid']
        else:
            _sid = ''

        if 'id_token_hint' in request:
            _ith_sid = _sdb.sso_db.get_sids_by_sub(
                request[verified_claim_name("id_token_hint")]['sub'])[0]
            if _ith_sid != _sid:  # someone's messing with me
                raise ValueError('Wrong ID Token hint')

        session = _sdb[_sid]

        client_id = session['authn_req']['client_id']

        _cinfo = self.endpoint_context.cdb[client_id]

        # verify that the post_logout_redirect_uri if present are among the ones
        # registered

        try:
            _url_q = splitquery(request['post_logout_redirect_uri'])
        except KeyError:
            pass
        else:
            if not _url_q in _cinfo['post_logout_redirect_uris']:
                raise ValueError('Unregistered post_logout_redirect_uri')

        # Kill the session
        _sdb.revoke_session(sid=_sid)

        if 'post_logout_redirect_uri' in request:
            _ruri = request["post_logout_redirect_uri"]
            if 'state' in request:
                _ruri = '{}?{}'.format(
                    _ruri, urlencode({'state': request['state']}))
        else:  # To  my own logout-done page
            try:
                _ruri = self.endpoint_context.conf['post_logout_page']
            except KeyError:
                _ruri = self.endpoint_context.issuer

        return {
            'response_args': _ruri
            }

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
        try:
            auth_info = self.client_authentication(request, auth, **kwargs)
        except UnknownOrNoAuthnMethod:
            pass
        else:
            if isinstance(auth_info, ResponseMessage):
                return auth_info
            else:
                request['client_id'] = auth_info['client_id']
                request['access_token'] = auth_info['token']

        if isinstance(request, dict):
            request = self.request_cls(**request)
            if not request.verify(keyjar=self.endpoint_context.keyjar,
                                  sigalg=''):
                raise InvalidRequest("Didn't verify")
            # id_token_signing_alg_values_supported
            _ith = request[verified_claim_name("id_token_hint")]
            if _ith.jws_header['alg'] not in \
                    self.endpoint_context.provider_info[
                        'id_token_signing_alg_values_supported']:
                raise JWSException('Unsupported signing algorithm')

        return request
