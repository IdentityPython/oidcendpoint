import pytest
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.session.info import ClientSessionInfo
from oidcendpoint.session.info import SessionInfo
from oidcendpoint.session.info import UserSessionInfo

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid"],
    state="STATE",
    response_type=["code"],
)


def test_session_info_subordinate():
    si = SessionInfo()
    si.add_subordinate("subordinate_1")
    si.add_subordinate("subordinate_2")
    assert set(si["subordinate"]) == {"subordinate_1", "subordinate_2"}
    assert set(si["subordinate"]) == {"subordinate_1", "subordinate_2"}
    assert si.is_revoked() is False

    si.remove_subordinate("subordinate_1")
    assert si["subordinate"] == ["subordinate_2"]

    si.revoke()
    assert si.is_revoked() is True


def test_session_info_no_subordinate():
    si = SessionInfo()
    assert si["subordinate"] == []


def test_user_session_info_to_json():
    authn_event = AuthnEvent(uid="uid",
                             valid_until=time_sans_frac() + 1,
                             authn_info="authn_class_ref")

    usi = UserSessionInfo(authentication_event=authn_event)

    _jstr = usi.to_json()

    usi2 = UserSessionInfo().from_json(_jstr)

    assert usi2["authentication_event"]["uid"] == "uid"


def test_user_session_info_to_json_with_sub():
    authn_event = AuthnEvent(uid="uid",
                             valid_until=time_sans_frac() + 1,
                             authn_info="authn_class_ref")

    usi = UserSessionInfo(authentication_event=authn_event)
    usi.add_subordinate("client_session_id")

    _jstr = usi.to_json()

    usi2 = UserSessionInfo().from_json(_jstr)

    assert usi2["subordinate"] == ["client_session_id"]


def test_client_session_info():
    csi = ClientSessionInfo(authorization_request=AUTH_REQ)
    csi.sub = "Subject ID"

    _jstr = csi.to_json()

    _csi2 = ClientSessionInfo().from_json(_jstr)
    assert _csi2["authorization_request"]["response_type"] == "code"
