import json
import os

from oidcendpoint.authn_event import create_authn_event
from oidcmsg.message import Message
from oidcmsg.oidc import OpenIDRequest
from oidcmsg.oidc import OpenIDSchema
from oidcendpoint.endpoint_context import EndpointContext
from oidcendpoint.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from oidcendpoint.user_info import UserInfo
from oidcendpoint.userinfo import by_schema
from oidcendpoint.userinfo import claims_match
from oidcendpoint.userinfo import collect_user_info
from oidcendpoint.userinfo import update_claims

CLAIMS = {
    "userinfo": {
        "given_name": {"essential": True},
        "nickname": None,
        "email": {"essential": True},
        "email_verified": {"essential": True},
        "picture": None,
        "http://example.info/claims/groups": {'value': 'red'}
        },
    "id_token": {
        "auth_time": {"essential": True},
        "acr": {"values": ["urn:mace:incommon:iap:silver"]}
        }
    }

OIDR = OpenIDRequest(response_type="code", client_id="client1",
                     redirect_uri="http://example.com/authz", scope=["openid"],
                     state="state000", claims=CLAIMS)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


USERINFO_DB = json.loads(open(full_path('users.json')).read())


def test_update_claims_authn_req_id_token():
    _session_info = {'authn_req': OIDR}
    claims = update_claims(_session_info, 'id_token')
    assert set(claims.keys()) == {'auth_time', 'acr'}


def test_update_claims_authn_req_userinfo():
    _session_info = {'authn_req': OIDR}
    claims = update_claims(_session_info, 'userinfo')
    assert set(claims.keys()) == {'given_name', 'nickname', 'email',
                                  'email_verified', 'picture',
                                  'http://example.info/claims/groups'}


def test_update_claims_authzreq_id_token():
    _session_info = {'authn_req': OIDR}
    claims = update_claims(_session_info, 'id_token')
    assert set(claims.keys()) == {'auth_time', 'acr'}


def test_update_claims_authzreq_userinfo():
    _session_info = {'authn_req': OIDR}
    claims = update_claims(_session_info, 'userinfo')
    assert set(claims.keys()) == {'given_name', 'nickname', 'email',
                                  'email_verified', 'picture',
                                  'http://example.info/claims/groups'}


def test_clams_value():
    assert claims_match('red',
                        CLAIMS['userinfo']["http://example.info/claims/groups"])


def test_clams_values():
    assert claims_match("urn:mace:incommon:iap:silver",
                        CLAIMS['id_token']['acr'])


def test_clams_essential():
    assert claims_match(['foobar@example'],
                        CLAIMS['userinfo']['email'])


def test_clams_none():
    assert claims_match(['angle'],
                        CLAIMS['userinfo']['nickname'])


def test_by_schema():
    # There are no requested or optional claims defined for Message
    assert by_schema(Message, sub='John') == {}

    assert by_schema(OpenIDSchema, sub='John', given_name='John', age=34) == {
        'sub': 'John', 'given_name': 'John'
        }


def test_collect_user_info():
    _session_info = {'authn_req': OIDR}
    session = _session_info.copy()
    session['sub'] = 'doe'
    session['uid'] = 'diana'
    session['authn_event'] = create_authn_event('diana', 'salt')

    endpoint_context = EndpointContext({
        'userinfo': {
            'class': UserInfo,
            'kwargs': {'db': USERINFO_DB}
            },
        'password': "we didn't start the fire",
        'issuer': 'https://example.com/op',
        'token_expires_in': 900, 'grant_expires_in': 600,
        'refresh_token_expires_in': 86400,
        "endpoint": {},
        "authentication": [{
            'acr': INTERNETPROTOCOLPASSWORD,
            'name': 'NoAuthn',
            'kwargs': {'user': 'diana'}
            }],
        'template_dir': 'template'
        })

    res = collect_user_info(endpoint_context, session)

    assert res == {
        'given_name': 'Diana', 'nickname': 'Dina', 'sub': 'doe',
        'email': 'diana@example.org', 'email_verified': False
    }
