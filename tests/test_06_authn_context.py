from oidcmsg.time_util import time_sans_frac

from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.endpoint_context import populate_authn_broker
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_authn.user import NoAuthn

METHOD = {
    'diana': {
        'acr': INTERNETPROTOCOLPASSWORD,
        'kwargs': {'user': 'diana'},
        'class': 'oidcendpoint.user_authn.user.NoAuthn'
    },
    'krall': {
        'acr': INTERNETPROTOCOLPASSWORD,
        'kwargs': {'user': 'krall'},
        'class': NoAuthn
    }
}


class TestAuthnBroker():

    def test_1(self):
        authn_broker = populate_authn_broker(METHOD, None)
        assert len(authn_broker) == 2

    def test_2(self):
        authn_broker = populate_authn_broker(METHOD, None)
        method = list(authn_broker.get_method('NoAuthn'))
        assert len(method) == 2

    def test_3(self):
        authn_broker = populate_authn_broker(METHOD, None)
        method, acr = authn_broker.get_method_by_id('diana')
        assert method.user == 'diana'
        method, acr = authn_broker.get_method_by_id('krall')
        assert method.user == 'krall'


def test_authn_event():
    an = AuthnEvent(uid='uid', salt='_salt_', valid_until=time_sans_frac() + 1,
                    authn_info='authn_class_ref')

    assert an.valid()

    n = time_sans_frac() + 3
    assert an.valid(n) is False

    n = an.expires_in()
    assert n == 1  # could possibly be 0
