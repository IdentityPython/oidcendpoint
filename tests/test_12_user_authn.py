import os

import pytest

from oidcendpoint.cookie import cookie_value
from oidcendpoint.cookie import new_cookie
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_authn.authn_context import UNSPECIFIED
from oidcendpoint.user_authn.user import NoAuthn
from oidcendpoint.user_authn.user import UserPassJinja2
from oidcendpoint.util import JSONDictDB

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


class TestUserAuthn(object):
    @pytest.fixture(autouse=True)
    def create_endpoint_context(self):
        conf = {
            "issuer": "https://example.com/",
            "password": "mycket hemligt",
            "token_expires_in": 600,
            "grant_expires_in": 300,
            "refresh_token_expires_in": 86400,
            "verify_ssl": False,
            "endpoint": {},
            "jwks": {
                'uri_path': 'static/jwks.json',
                'key_defs': KEYDEFS,
            },
            'authentication': {
                'user':
                    {
                        'acr': INTERNETPROTOCOLPASSWORD,
                        'class': UserPassJinja2,
                        'verify_endpoint': 'verify/user',
                        'kwargs': {
                            'template': 'user_pass.jinja2',
                            'sym_key': '24AA/LR6HighEnergy',
                            'db': {
                                'class': JSONDictDB,
                                'kwargs':
                                    {'json_path': full_path('passwd.json')}
                            },
                            'page_header': "Testing log in",
                            'submit_btn': "Get me in!",
                            'user_label': "Nickname",
                            'passwd_label': "Secret sauce"
                        }
                    },
                'anon':
                    {
                        'acr': UNSPECIFIED,
                        'class': NoAuthn,
                        'kwargs': {'user': 'diana'}
                    }
            },
            'cookie_dealer': {
                'class': 'oidcendpoint.cookie.CookieDealer',
                'kwargs': {
                    'symkey': 'ghsNKDDLshZTPn974nOsIGhedULrsqnsGoBFBLwUKuJhE2ch',
                    'default_values': {
                        'name': 'oidc_op',
                        'domain': 'example.com',
                        'path': '/',
                        'max_age': 3600
                    }
                }
            },
            'template_dir': 'template'
        }
        self.endpoint_context = EndpointContext(conf)

    def test_authenticated_as_without_cookie(self):
        authn_item = self.endpoint_context.authn_broker.pick(
            INTERNETPROTOCOLPASSWORD)
        method = authn_item[0]['method']

        _info, _time_stamp = method.authenticated_as(None)
        assert _info is None

    def test_authenticated_as_with_cookie(self):
        authn_item = self.endpoint_context.authn_broker.pick(
            INTERNETPROTOCOLPASSWORD)
        method = authn_item[0]['method']

        cookie = new_cookie(self.endpoint_context, uid='diana')

        _info, _time_stamp = method.authenticated_as(cookie)
        _info = cookie_value(_info['uid'])
        assert _info['uid'] == 'diana'

