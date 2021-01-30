from typing import Tuple

from oidcmsg.message import OPTIONAL_LIST_OF_MESSAGES
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_BOOLEAN
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import Message
from oidcmsg.message import list_deserializer
from oidcmsg.message import list_serializer

from oidcendpoint.session.grant import Grant
from oidcendpoint.session.token import Token


class SessionInfo(Message):
    c_param = {
        "subordinate": ([str], False, list_serializer, list_deserializer, True),
        "revoked": SINGLE_REQUIRED_BOOLEAN,
        "type": SINGLE_REQUIRED_STRING
    }

    def __init__(self, **kwargs):
        Message.__init__(self, **kwargs)
        if "subordinate" not in self:
            self["subordinate"] = []
        self["revoked"] = False

    def add_subordinate(self, value: str) -> "SessionInfo":
        if value not in self["subordinate"]:
            self["subordinate"].append(value)
        return self

    def remove_subordinate(self, value: str) -> 'SessionInfo':
        self["subordinate"].remove(value)
        return self

    def revoke(self) -> 'SessionInfo':
        self["revoked"] = True
        return self

    def is_revoked(self) -> bool:
        return self["revoked"]


class UserSessionInfo(SessionInfo):
    c_param = SessionInfo.c_param.copy()
    c_param.update({
        "user_id": SINGLE_REQUIRED_STRING,
    })

    def __init__(self, **kwargs):
        SessionInfo.__init__(self, **kwargs)
        self["type"] = "UserSessionInfo"


class ClientSessionInfo(SessionInfo):
    c_param = SessionInfo.c_param.copy()
    c_param.update({
        "client_id": SINGLE_REQUIRED_STRING
    })

    def __init__(self, **kwargs):
        SessionInfo.__init__(self, **kwargs)
        self["type"] = "ClientSessionInfo"

    def find_grant_and_token(self, val: str) -> Tuple[Grant, Token]:
        for grant in self["subordinate"]:
            token = grant.get_token(val)
            if token:
                return grant, token
