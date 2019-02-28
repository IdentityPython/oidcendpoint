import logging

from urllib.parse import urlparse

from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import MissingRequiredValue
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage

from oidcendpoint import sanitize
from oidcendpoint.client_authn import UnknownOrNoAuthnMethod
from oidcendpoint.client_authn import verify_client
from oidcendpoint.exception import UnAuthorizedClient
from oidcendpoint.util import OAUTH2_NOCACHE_HEADERS

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

"""
method call structure for Endpoints:

parse_request
    - client_authentication (*)
    - post_parse_request (*)
    
process_request

do_response    
    - response_info
        - construct 
            - pre_construct (*)
            - _parse_args
            - post_construct (*)
    - update_http_args
"""


def set_content_type(headers, content_type):
    if ('Content-type', content_type) in headers:
        return headers

    _headers = [h for h in headers if h[0] != 'Content-type']
    _headers.append(('Content-type', content_type))
    return _headers


def fragment_encoding(return_type):
    if return_type == ['code']:
        return False
    else:
        return True


class Endpoint(object):
    request_cls = Message
    response_cls = Message
    error_cls = ResponseMessage
    endpoint_name = ''
    endpoint_path = ''
    request_format = 'urlencoded'
    request_placement = 'query'
    response_format = 'json'
    response_placement = 'body'
    client_auth_method = ''

    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.pre_construct = []
        self.post_construct = []
        self.post_parse_request = []
        self.kwargs = kwargs
        self.full_path = ''
        self.provider_info = None

    def parse_request(self, request, auth=None, **kwargs):
        """

        :param request: The request the server got
        :param auth: Client authentication information
        :param kwargs: extra keyword arguments
        :return:
        """
        logger.debug("- {} -".format(self.endpoint_name))
        logger.info("Request: %s" % sanitize(request))

        if request:
            if isinstance(request, dict):
                req = self.request_cls(**request)
            else:
                if self.request_format == 'jwt':
                    req = self.request_cls().deserialize(
                        request, "jwt", keyjar=self.endpoint_context.keyjar,
                        verify=self.endpoint_context.verify_ssl, **kwargs)
                elif self.request_format == 'url':
                    parts = urlparse(request)
                    scheme, netloc, path, params, query, fragment = parts[:6]
                    req = self.request_cls().deserialize(query, 'urlencoded')
                else:
                    req = self.request_cls().deserialize(request,
                                                         self.request_format)
        else:
            req = self.request_cls()

        # Verify that the client is allowed to do this
        _client_id = ''
        try:
            auth_info = self.client_authentication(req, auth, **kwargs)
        except UnknownOrNoAuthnMethod:
            if not self.client_auth_method:
                try:
                    _client_id = req['client_id']
                except KeyError:
                    _client_id = ''
            else:
                raise UnAuthorizedClient()
        else:
            if 'client_id' in auth_info:
                req['client_id'] = auth_info['client_id']
                _client_id = auth_info['client_id']
            else:
                try:
                    _client_id = req['client_id']
                except KeyError:
                    pass

        try:
            keyjar = self.endpoint_context.keyjar
        except AttributeError:
            keyjar = ""

        # verify that the request message is correct
        try:
            req.verify(keyjar=keyjar, opponent_id=_client_id)
        except (MissingRequiredAttribute, ValueError,
                MissingRequiredValue) as err:
            return self.error_cls(error="invalid_request",
                                  error_description="%s" % err)

        logger.info("Parsed and verified request: %s" % sanitize(req))

        # Do any endpoint specific parsing
        return self.do_post_parse_request(req, _client_id, **kwargs)

    def client_authentication(self, request, auth=None, **kwargs):
        """

        :param endpoint_context: A
        :py:class:`oidcendpoint.endpoint_context.SrvInfo` instance
        :param request: Parsed request, a self.request_cls class instance
        :param authn: Authorization info
        :return: client_id or raise and exception
        """

        return verify_client(self.endpoint_context, request, auth)

    def do_post_parse_request(self, request, client_id='', **kwargs):
        for meth in self.post_parse_request:
            request = meth(request, client_id,
                           endpoint_context=self.endpoint_context, **kwargs)
        return request

    def do_pre_construct(self, response_args, request, **kwargs):
        for meth in self.pre_construct:
            response_args = meth(response_args, request,
                                 endpoint_context=self.endpoint_context,
                                 **kwargs)

        return response_args

    def do_post_construct(self, response_args, request, **kwargs):
        for meth in self.post_construct:
            response_args = meth(response_args, request,
                                 endpoint_context=self.endpoint_context,
                                 **kwargs)

        return response_args

    def process_request(self, request=None, **kwargs):
        """

        :param request: The request, can be in a number of formats
        :return: Arguments for the do_response method
        """
        return {}

    def construct(self, response_args, request, **kwargs):
        """
        Construct the response

        :param response_args: response arguments
        :param request: The parsed request, a self.request_cls class instance
        :param kwargs: Extra keyword arguments
        :return: An instance of the self.response_cls class
        """
        response_args = self.do_pre_construct(response_args, request, **kwargs)

        # logger.debug("kwargs: %s" % sanitize(kwargs))
        response = self.response_cls(**response_args)

        return self.do_post_construct(response, request, **kwargs)

    def response_info(self, response_args, request, **kwargs):
        return self.construct(response_args, request, **kwargs)

    def do_response(self, response_args=None, request=None, error='', **kwargs):
        do_placement = True
        content_type = 'text/html'
        _resp = {}

        if response_args is None:
            response_args = {}

        resp = None
        if error:
            _response = ResponseMessage(error=error)
            try:
                _response['error_description'] = kwargs['error_description']
            except KeyError:
                pass
        elif 'response_msg' in kwargs:
            resp = kwargs['response_msg']
            do_placement = False
            _response = ''  # This is just for my IDE
            if self.response_format == 'json':
                content_type = 'application/json'
            elif self.request_format in ['jws', 'jwe', 'jose']:
                content_type = 'application/jose'
            else:
                content_type = 'application/x-www-form-urlencoded'
        else:
            _response = self.response_info(response_args, request, **kwargs)

        if do_placement:
            if self.response_placement == 'body':
                if self.response_format == 'json':
                    content_type = 'application/json'
                    resp = _response.to_json()
                elif self.request_format in ['jws','jwe','jose']:
                    content_type = 'application/jose'
                    resp = _response
                else:
                    content_type = 'application/x-www-form-urlencoded'
                    resp = _response.to_urlencoded()
            elif self.response_placement == 'url':
                # content_type = 'application/x-www-form-urlencoded'
                content_type = ''
                try:
                    fragment_enc = kwargs['fragment_enc']
                except KeyError:
                    fragment_enc = fragment_encoding(kwargs['return_type'])

                if fragment_enc:
                    resp = _response.request(kwargs['return_uri'], True)
                else:
                    resp = _response.request(kwargs['return_uri'])
            else:
                raise ValueError(
                    "Don't know where that is: '{}".format(self.response_placement))

        if content_type:
            try:
                http_headers = set_content_type(kwargs['http_headers'],
                                                content_type)
            except KeyError:
                http_headers = [('Content-type', content_type)]
        else:
            try:
                http_headers = kwargs['http_headers']
            except KeyError:
                http_headers = []

        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        _resp.update({'response': resp, 'http_headers': http_headers})

        try:
            _resp['cookie'] = kwargs['cookie']
        except KeyError:
            pass

        return _resp
