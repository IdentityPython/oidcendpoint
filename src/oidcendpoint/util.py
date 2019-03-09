import importlib
import json
import logging

from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64e

logger = logging.getLogger(__name__)

OAUTH2_NOCACHE_HEADERS = [
    ('Pragma', 'no-cache'),
    ('Cache-Control', 'no-store'),
]


def new_cookie(endpoint_context, cookie_name=None, **kwargs):
    if endpoint_context.cookie_dealer:
        _val = as_unicode(b64e(as_bytes(json.dumps(kwargs))))
        return endpoint_context.cookie_dealer.create_cookie(
            _val, typ="sso", cookie_name=cookie_name,
            ttl=endpoint_context.sso_ttl)
    else:
        return None


def modsplit(s):
    """Split importable"""
    if ':' in s:
        c = s.split(':')
        if len(c) != 2:
            raise ValueError("Syntax error: {s}")
        return c[0], c[1]
    else:
        c = s.split('.')
        if len(c) < 2:
            raise ValueError("Syntax error: {s}")
        return '.'.join(c[:-1]), c[-1]


def importer(name):
    """Import by name"""
    c1, c2 = modsplit(name)
    module = importlib.import_module(c1)
    return getattr(module, c2)


def build_endpoints(conf, endpoint_context, client_authn_method, issuer):
    """
    conf typically contains::

        'provider_config': {
            'path': '.well-known/openid-configuration',
            'class': ProviderConfiguration,
            'kwargs': {}
        },

    :param conf:
    :param endpoint_context:
    :param client_authn_method:
    :param issuer:
    :return:
    """

    if issuer.endswith('/'):
        _url = issuer[:-1]
    else:
        _url = issuer

    endpoint = {}
    for name, spec in conf.items():
        try:
            kwargs = spec['kwargs']
        except KeyError:
            kwargs = {}

        if isinstance(spec['class'], str):
            _instance = importer(spec['class'])(
                endpoint_context=endpoint_context, **kwargs)
        else:
            _instance = spec['class'](endpoint_context=endpoint_context,
                                      **kwargs)

        _instance.endpoint_path = spec['path']
        _instance.full_path = '{}/{}'.format(_url, spec['path'])
        if 'provider_info' in spec:
            _instance.provider_info = spec['provider_info']

        try:
            _client_authn_method = kwargs['client_authn_method']
        except KeyError:
            _instance.client_auth_method = client_authn_method
        else:
            _instance.client_auth_method = _client_authn_method

        endpoint[name] = _instance

    return endpoint


class JSONDictDB(object):
    def __init__(self, json_path):
        with open(json_path, "r") as f:
            self._db = json.load(f)

    def __getitem__(self, item):
        return self._db[item]

    def __contains__(self, item):
        return item in self._db


def instantiate(cls, **kwargs):
    if isinstance(cls, str):
        return importer(cls)(**kwargs)
    else:
        return cls(**kwargs)
