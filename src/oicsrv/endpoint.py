import logging
# noinspection PyCompatibility
from urllib.parse import urlparse

from oicmsg.exception import MissingRequiredAttribute
from oicmsg.exception import MissingRequiredValue
from oicmsg.message import Message
from oicmsg.oauth2 import ErrorResponse

from oicsrv import sanitize
from oicsrv.client_authn import UnknownOrNoAuthnMethod
from oicsrv.client_authn import verify_client
from oicsrv.exception import UnAuthorizedClient
from oicsrv.util import OAUTH2_NOCACHE_HEADERS

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


class Endpoint(object):
    request_cls = Message
    response_cls = Message
    error_cls = ErrorResponse
    endpoint_name = ''
    endpoint_path = ''
    request_format = 'urlencoded'
    request_placement = 'query'
    response_format = 'json'
    response_placement = 'body'
    client_auth_method = ''

    def __init__(self, keyjar, **kwargs):
        self.keyjar = keyjar
        self.pre_construct = []
        self.post_construct = []
        self.post_parse_request = []
        self.kwargs = kwargs

    def parse_request(self, srv_info, request, auth=None, **kwargs):
        """

        :param request:
        :param srv_info:
        :param auth:
        :param kwargs:
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
                        request, "jwt", keyjar=srv_info.keyjar,
                        verify=srv_info.verify_ssl, **kwargs)
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
            _client_id = self.client_authentication(srv_info, req, auth, **kwargs)
        except UnknownOrNoAuthnMethod:
            if not self.client_auth_method:
                pass
            else:
                raise UnAuthorizedClient()
        else:
            if _client_id:
                req['client_id'] = _client_id
            else:
                try:
                    _client_id = req['client_id']
                except KeyError:
                    pass

        try:
            keyjar = self.keyjar
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
        if srv_info.events:
            srv_info.events.store('Protocol request', request)

        # Do any endpoint specific parsing
        self.do_post_parse_request(srv_info, req, _client_id, **kwargs)
        return req

    def client_authentication(self, srv_info, request, auth=None, **kwargs):
        """

        :param srv_info: A :py:class:`oicsrv.srv_info.SrvInfo` instance
        :param request: Parsed request, a self.request_cls class instance
        :param authn: Authorization info
        :return: client_id or raise and exception
        """

        return verify_client(srv_info, request, auth)

    def do_post_parse_request(self, srv_info, request, client_id='', **kwargs):
        for meth in self.post_parse_request:
            request = meth(srv_info, request, client_id, **kwargs)
        return request

    def do_pre_construct(self, srv_info, response_args, request, **kwargs):
        for meth in self.pre_construct:
            response_args = meth(srv_info, response_args, request, **kwargs)

        return response_args

    def do_post_construct(self, srv_info, response_args, request, **kwargs):
        for meth in self.post_construct:
            response_args = meth(srv_info, response_args, request, **kwargs)

        return response_args

    def process_request(self, srv_info, request=None):
        """

        :param srv_info: :py:class:`oicsrv.srv_info.SrvInfo` instance
        :param request: The request, can be in a number of formats
        :return: response arguments
        """
        return {}

    def construct(self, srv_info, response_args, request, **kwargs):
        """
        Construct the response

        :param srv_info: :py:class:`oicsrv.srv_info.SrvInfo` instance
        :param response_args: response arguments
        :param request: The parsed request, a self.request_cls class instance
        :param kwargs: Extra keyword arguments
        :return: An instance of the self.response_cls class
        """
        response_args = self.do_pre_construct(srv_info, response_args, request,
                                              **kwargs)

        # logger.debug("kwargs: %s" % sanitize(kwargs))
        response = self.response_cls(**response_args)

        return self.do_post_construct(srv_info, response, request, **kwargs)

    def response_info(self, srv_info, response_args, request, **kwargs):
        return self.construct(srv_info, response_args, request, **kwargs)

    def do_response(self, srv_info, response_args=None, request=None, **kwargs):
        if response_args is None:
            response_args = {}

        _response = self.response_info(srv_info, response_args, request,
                                       **kwargs)
        if isinstance(_response, ErrorResponse):
            return _response

        if self.response_placement == 'body':
            if self.response_format == 'json':
                content_type = 'application/json'
                resp = _response.to_json()
            else:
                content_type = 'application/x-www-form-urlencoded'
                resp = _response.to_urlencoded()
        elif self.response_placement == 'url':
            content_type = 'application/x-www-form-urlencoded'
            try:
                fragment_enc = kwargs['fragment_enc']
            except KeyError:
                fragment_enc = False

            if fragment_enc:
                resp = _response.request(kwargs['return_uri'], True)
            else:
                resp = _response.request(kwargs['return_uri'])
        else:
            raise ValueError(
                "Don't know where that is: '{}".format(self.response_placement))

        try:
            http_headers = set_content_type(kwargs['http_headers'],
                                            content_type)
        except KeyError:
            http_headers = [('Content-type', content_type)]
        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        return {'response': resp, 'http_headers': http_headers}


