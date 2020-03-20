import logging
from functools import cmp_to_key
from urllib.parse import urlparse

from cryptojwt import jwe
from cryptojwt.jws.jws import SIGNER_ALGS
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import MissingRequiredValue
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage

from oidcendpoint import sanitize
from oidcendpoint.client_authn import UnknownOrNoAuthnMethod
from oidcendpoint.client_authn import client_auth_setup
from oidcendpoint.client_authn import verify_client
from oidcendpoint.exception import UnAuthorizedClient
from oidcendpoint.util import OAUTH2_NOCACHE_HEADERS

__author__ = "Roland Hedberg"

LOGGER = logging.getLogger(__name__)

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

do_response returns a dictionary that can look like this:
{
  'response':
    _response as a string or as a Message instance_
  'http_headers': [
    ('Content-type', 'application/json'),
    ('Pragma', 'no-cache'),
    ('Cache-Control', 'no-store')
  ],
  'cookie': _list of cookies_,
  'response_placement': 'body'
}

"response" MUST be present
"http_headers" MAY be present
"cookie": MAY be present
"response_placement": If absent defaults to the endpoints response_placement
    parameter value or if that is also missing 'url'
"""


def set_content_type(headers, content_type):
    if ("Content-type", content_type) in headers:
        return headers

    _headers = [h for h in headers if h[0] != "Content-type"]
    _headers.append(("Content-type", content_type))
    return _headers


def fragment_encoding(return_type):
    if return_type == ["code"]:
        return False
    else:
        return True


ALG_SORT_ORDER = {"RS": 0, "ES": 1, "HS": 2, "PS": 3, "no": 4}


def sort_sign_alg(alg1, alg2):
    if ALG_SORT_ORDER[alg1[0:2]] < ALG_SORT_ORDER[alg2[0:2]]:
        return -1

    if ALG_SORT_ORDER[alg1[0:2]] > ALG_SORT_ORDER[alg2[0:2]]:
        return 1

    if alg1 < alg2:
        return -1

    if alg1 > alg2:
        return 1

    return 0


def assign_algorithms(typ):
    if typ == "signing_alg":
        # Pick supported signing algorithms from crypto library
        # Sort order RS, ES, HS, PS
        sign_algs = list(SIGNER_ALGS.keys())
        return sorted(sign_algs, key=cmp_to_key(sort_sign_alg))
    elif typ == "encryption_alg":
        return jwe.SUPPORTED["alg"]
    elif typ == "encryption_enc":
        return jwe.SUPPORTED["enc"]


def construct_endpoint_info(default_capabilities, **kwargs):
    if default_capabilities is not None:
        _info = {}
        for attr, default_val in default_capabilities.items():
            try:
                _proposal = kwargs[attr]
            except KeyError:
                if default_val is not None:
                    _info[attr] = default_val
                elif "signing_alg_values_supported" in attr:
                    _info[attr] = assign_algorithms("signing_alg")
                elif "encryption_alg_values_supported" in attr:
                    _info[attr] = assign_algorithms("encryption_alg")
                elif "encryption_enc_values_supported" in attr:
                    _info[attr] = assign_algorithms("encryption_enc")
            else:
                _permitted = None

                if "signing_alg_values_supported" in attr:
                    _permitted = set(assign_algorithms("signing_alg"))
                elif "encryption_alg_values_supported" in attr:
                    _permitted = set(assign_algorithms("encryption_alg"))
                elif "encryption_enc_values_supported" in attr:
                    _permitted = set(assign_algorithms("encryption_enc"))

                if _permitted and not _permitted.issuperset(set(_proposal)):
                    raise ValueError(
                        "Proposed set of values outside set of permitted ({})".__format__(
                            attr
                        )
                    )

                _info[attr] = _proposal
        return _info
    else:
        return None


class Endpoint(object):
    request_cls = Message
    response_cls = Message
    error_cls = ResponseMessage
    endpoint_name = ""
    endpoint_path = ""
    name = ""
    request_format = "urlencoded"
    request_placement = "query"
    response_format = "json"
    response_placement = "body"
    client_authn_method = ""
    default_capabilities = None

    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.pre_construct = []
        self.post_construct = []
        self.post_parse_request = []
        self.kwargs = kwargs
        self.full_path = ""

        for param in [
            "request_cls",
            "response_cls",
            "request_format",
            "request_placement",
            "response_format",
            "response_placement",
        ]:
            _val = kwargs.get(param)
            if _val:
                setattr(self, param, _val)

        _methods = kwargs.get("client_authn_method")
        if _methods:
            self.client_authn_method = client_auth_setup(_methods, endpoint_context)
        elif self.default_capabilities:
            _methods = self.default_capabilities.get("client_authn_method")
            if _methods:
                self.client_authn_method = client_auth_setup(_methods, endpoint_context)

        self.endpoint_info = construct_endpoint_info(
            self.default_capabilities, **kwargs
        )
        # This is for matching against aud in JWTs
        # By default the endpoint's endpoint URL is an allowed target
        self.allowed_targets = [self.name]

    def parse_request(self, request, auth=None, **kwargs):
        """

        :param request: The request the server got
        :param auth: Client authentication information
        :param kwargs: extra keyword arguments
        :return:
        """
        LOGGER.debug("- {} -".format(self.endpoint_name))
        LOGGER.info("Request: %s" % sanitize(request))

        if request:
            if isinstance(request, (dict, Message)):
                req = self.request_cls(**request)
            else:
                _cls_inst = self.request_cls()
                if self.request_format == "jwt":
                    req = _cls_inst.deserialize(
                        request,
                        "jwt",
                        keyjar=self.endpoint_context.keyjar,
                        verify=self.endpoint_context.httpc_params["verify"],
                        **kwargs
                    )
                elif self.request_format == "url":
                    parts = urlparse(request)
                    scheme, netloc, path, params, query, fragment = parts[:6]
                    req = _cls_inst.deserialize(query, "urlencoded")
                else:
                    req = _cls_inst.deserialize(request, self.request_format)
        else:
            req = self.request_cls()

        # Verify that the client is allowed to do this
        _client_id = ""
        try:
            auth_info = self.client_authentication(req, auth, endpoint=self.name, **kwargs)
        except UnknownOrNoAuthnMethod:
            # If there is no required client authentication method
            if not self.client_authn_method:
                try:
                    _client_id = req["client_id"]
                except KeyError:
                    _client_id = ""
            else:
                raise
        else:
            if "client_id" in auth_info:
                req["client_id"] = auth_info["client_id"]
                _client_id = auth_info["client_id"]
            else:
                _client_id = req.get("client_id")

        keyjar = self.endpoint_context.keyjar

        # verify that the request message is correct
        try:
            req.verify(keyjar=keyjar, opponent_id=_client_id)
        except (MissingRequiredAttribute, ValueError, MissingRequiredValue) as err:
            return self.error_cls(error="invalid_request", error_description="%s" % err)

        LOGGER.info("Parsed and verified request: %s" % sanitize(req))

        # Do any endpoint specific parsing
        return self.do_post_parse_request(req, _client_id, **kwargs)

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        return ""

    def client_authentication(self, request, auth=None, **kwargs):
        """
        Do client authentication

        :param endpoint_context: A
            :py:class:`oidcendpoint.endpoint_context.SrvInfo` instance
        :param request: Parsed request, a self.request_cls class instance
        :param authn: Authorization info
        :return: client_id or raise an exception
        """

        try:
            authn_info = verify_client(
                self.endpoint_context, request, auth, self.get_client_id_from_token, **kwargs
            )
        except UnknownOrNoAuthnMethod:
            if self.client_authn_method is None:
                return {}
            else:
                if "none" in self.client_authn_method:
                    return {}
                else:
                    raise

        if authn_info == {} and self.client_authn_method and len(self.client_authn_method):
            raise UnAuthorizedClient("Authorization failed")

        return authn_info

    def do_post_parse_request(self, request, client_id="", **kwargs):
        for meth in self.post_parse_request:
            request = meth(
                request, client_id, endpoint_context=self.endpoint_context, **kwargs
            )
        return request

    def do_pre_construct(self, response_args, request, **kwargs):
        for meth in self.pre_construct:
            response_args = meth(
                response_args, request, endpoint_context=self.endpoint_context, **kwargs
            )

        return response_args

    def do_post_construct(self, response_args, request, **kwargs):
        for meth in self.post_construct:
            response_args = meth(
                response_args, request, endpoint_context=self.endpoint_context, **kwargs
            )

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

        # LOGGER.debug("kwargs: %s" % sanitize(kwargs))
        response = self.response_cls(**response_args)

        return self.do_post_construct(response, request, **kwargs)

    def response_info(self, response_args, request, **kwargs):
        return self.construct(response_args, request, **kwargs)

    def do_response(self, response_args=None, request=None, error="", **kwargs):
        """

        """
        do_placement = True
        content_type = "text/html"
        _resp = {}
        _response_placement = None
        if response_args is None:
            response_args = {}

        LOGGER.debug("do_response kwargs: %s", kwargs)

        resp = None
        if error:
            _response = ResponseMessage(error=error)
            try:
                _response["error_description"] = kwargs["error_description"]
            except KeyError:
                pass
        elif "response_msg" in kwargs:
            resp = kwargs["response_msg"]
            _response_placement = kwargs.get('response_placement')
            do_placement = False
            _response = ""
            content_type = kwargs.get('content_type')
            if content_type is None:
                if self.response_format == "json":
                    content_type = "application/json"
                elif self.request_format in ["jws", "jwe", "jose"]:
                    content_type = "application/jose"
                else:
                    content_type = "application/x-www-form-urlencoded"
        else:
            _response = self.response_info(response_args, request, **kwargs)

        if do_placement:
            content_type = kwargs.get('content_type')
            if content_type is None:
                if self.response_placement == "body":
                    if self.response_format == "json":
                        content_type = "application/json"
                        resp = _response.to_json()
                    elif self.request_format in ["jws", "jwe", "jose"]:
                        content_type = "application/jose"
                        resp = _response
                    else:
                        content_type = "application/x-www-form-urlencoded"
                        resp = _response.to_urlencoded()
                elif self.response_placement == "url":
                    # content_type = 'application/x-www-form-urlencoded'
                    content_type = ""
                    try:
                        fragment_enc = kwargs["fragment_enc"]
                    except KeyError:
                        _ret_type = kwargs.get("return_type")
                        if _ret_type:
                            fragment_enc = fragment_encoding(_ret_type)
                        else:
                            fragment_enc = False

                    if fragment_enc:
                        resp = _response.request(kwargs["return_uri"], True)
                    else:
                        resp = _response.request(kwargs["return_uri"])
                else:
                    raise ValueError(
                        "Don't know where that is: '{}".format(self.response_placement)
                    )

        if content_type:
            try:
                http_headers = set_content_type(kwargs["http_headers"], content_type)
            except KeyError:
                http_headers = [("Content-type", content_type)]
        else:
            try:
                http_headers = kwargs["http_headers"]
            except KeyError:
                http_headers = []

        if _response_placement:
            _resp["response_placement"] = _response_placement

        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        _resp.update({"response": resp, "http_headers": http_headers})

        try:
            _resp["cookie"] = kwargs["cookie"]
        except KeyError:
            pass

        return _resp

    def allowed_target_uris(self):
        res = []
        for t in self.allowed_targets:
            if t == "":
                res.append(self.endpoint_context.issuer)
            else:
                res.append(self.endpoint_context.endpoint[t].full_path)
        return set(res)
