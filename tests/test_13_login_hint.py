import os

from oidcendpoint.endpoint_context import init_service
from oidcendpoint.endpoint_context import init_user_info

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test_login_hint():
    userinfo = init_user_info({
                'class': 'oidcendpoint.user_info.UserInfo',
                'kwargs': {'db_file': full_path('users.json')}
            }, '')
    login_hint_lookup = init_service({
        'class': 'oidcendpoint.login_hint.LoginHintLookup'
    }, None)
    login_hint_lookup.userinfo = userinfo

    assert login_hint_lookup('tel:0907865000') == 'diana'