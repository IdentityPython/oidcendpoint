import json
from urllib.parse import urlparse

import pytest
from oidcmsg.key_jar import build_keyjar
from oidcmsg.message import Message

from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.endpoint_context import EndpointContext

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYJAR = build_keyjar(KEYDEFS)[1]

REQ = Message(foo='bar', hej='hopp')

EXAMPLE_MSG = {
    "name": "Jane Doe",
    "given_name": "Jane",
    "family_name": "Doe",
    "email": "janedoe@example.com",
    "picture": "http://example.com/janedoe/me.jpg"
}


def pre(args, request, endpoint_context):
    args.update({'name': '{}, {}'.format(args['family_name'],
                                         args['given_name'])})
    return args


def post(cis, request, endpoint_context):
    cis['request'] = request
    return cis


def test_endpoint_init():
    endp = Endpoint(endpoint_context=None)
    assert endp


class TestEndpoint(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {},
            "authentication": [{
                'acr': INTERNETPROTOCOLPASSWORD,
                'name': 'NoAuthn',
                'kwargs': {'user': 'diana'}
            }],
            'template_dir': 'template'
        }
        self.endpoint_context = EndpointContext(conf, keyjar=KEYJAR)
        self.endpoint = Endpoint(self.endpoint_context)

    def test_parse_urlencoded(self):
        self.endpoint.request_format = 'urlencoded'
        request = REQ.to_urlencoded()
        req = self.endpoint.parse_request(request)
        assert req == REQ

    def test_parse_url(self):
        self.endpoint.request_format = 'url'
        request = '{}?{}'.format(self.endpoint_context.issuer,
                                 REQ.to_urlencoded())
        req = self.endpoint.parse_request(request)
        assert req == REQ

    def test_parse_json(self):
        self.endpoint.request_format = 'json'
        request = REQ.to_json()
        req = self.endpoint.parse_request(request)
        assert req == REQ

    def test_parse_dict(self):
        # Doesn't matter what request_format is defined
        self.endpoint.request_format = 'json'
        request = REQ.to_dict()
        req = self.endpoint.parse_request(request)
        assert req == REQ

    def test_parse_jwt(self):
        self.endpoint.request_format = 'jwt'
        request = REQ.to_jwt(KEYJAR.get_signing_key('RSA'), 'RS256')
        req = self.endpoint.parse_request(request)
        assert req == REQ

    def test_construct(self):
        msg = self.endpoint.construct(EXAMPLE_MSG, {})
        assert set(msg.keys()) == set(EXAMPLE_MSG.keys())

    def test_pre_construct(self):
        self.endpoint.pre_construct.append(pre)
        msg = self.endpoint.construct(EXAMPLE_MSG, {})
        assert msg['name'] == 'Doe, Jane'

    def test_post_construct(self):
        self.endpoint.post_construct.append(post)
        msg = self.endpoint.construct(EXAMPLE_MSG, {})
        assert 'request' in msg

    def test_do_response_body_json(self):
        self.endpoint.response_placement = 'body'
        self.endpoint.response_format = 'json'
        msg = self.endpoint.do_response(EXAMPLE_MSG)

        assert isinstance(msg, dict)
        jmsg = json.loads(msg['response'])
        assert set(jmsg.keys()) == set(EXAMPLE_MSG.keys())

    def test_do_response_body_urlencoded(self):
        self.endpoint.response_placement = 'body'
        self.endpoint.response_format = 'urlencoded'
        msg = self.endpoint.do_response(EXAMPLE_MSG)

        assert isinstance(msg, dict)
        umsg = Message().from_urlencoded(msg['response'])
        assert set(umsg.keys()) == set(EXAMPLE_MSG.keys())

    def test_do_response_url_query(self):
        self.endpoint.response_placement = 'url'
        self.endpoint.response_format = 'urlencoded'
        msg = self.endpoint.do_response(EXAMPLE_MSG,
                                        fragment_enc=False,
                                        return_uri='https://example.org/cb')

        assert isinstance(msg, dict)
        parse_res = urlparse(msg['response'])
        assert parse_res.scheme == 'https'
        assert parse_res.netloc == 'example.org'
        assert parse_res.path == '/cb'
        umsg = Message().from_urlencoded(parse_res.query)
        assert set(umsg.keys()) == set(EXAMPLE_MSG.keys())

    def test_do_response_url_fragment(self):
        self.endpoint.response_placement = 'url'
        self.endpoint.response_format = 'urlencoded'
        msg = self.endpoint.do_response(EXAMPLE_MSG, fragment_enc=True,
                                        return_uri='https://example.org/cb_i')

        assert isinstance(msg, dict)
        parse_res = urlparse(msg['response'])
        assert parse_res.scheme == 'https'
        assert parse_res.netloc == 'example.org'
        assert parse_res.path == '/cb_i'
        umsg = Message().from_urlencoded(parse_res.fragment)
        assert set(umsg.keys()) == set(EXAMPLE_MSG.keys())
