import hashlib
import logging
from typing import List
from typing import Optional
import uuid

from oidcmsg.oauth2 import AuthorizationRequest

from oidcendpoint import rndstr
from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.token import handler
from . import unpack_session_key
from .database import Database
from .grant import ExchangeGrant
from .grant import Grant
from .grant import Token
from .info import ClientSessionInfo
from .info import UserSessionInfo
from ..token import UnknownToken
from ..token.handler import TokenHandler

logger = logging.getLogger(__name__)


def pairwise_id(uid, sector_identifier, salt="", **kwargs):
    return hashlib.sha256(("%s%s%s" % (uid, sector_identifier, salt)).encode("utf-8")).hexdigest()


def public_id(uid, salt="", **kwargs):
    return hashlib.sha256("{}{}".format(uid, salt).encode("utf-8")).hexdigest()


def ephemeral_id(*args, **kwargs):
    return uuid.uuid4().hex


class SessionManager(Database):
    def __init__(self, handler: TokenHandler, db: Optional[object] = None,
                 conf: Optional[dict] = None, sub_func: Optional[dict] = None):
        Database.__init__(self, db)
        self.token_handler = handler
        self.salt = rndstr(32)
        self.conf = conf or {}

        # this allows the subject identifier minters to be defined by someone
        # else then me.
        if sub_func is None:
            self.sub_func = {
                "public": public_id,
                "pairwise": pairwise_id,
                "ephemeral": ephemeral_id
            }
        else:
            self.sub_func = sub_func
            if "public" not in sub_func:
                self.sub_func["public"] = public_id
            if "pairwise" not in sub_func:
                self.sub_func["pairwise"] = pairwise_id
            if "ephemeral" not in sub_func:
                self.sub_func["ephemeral"] = ephemeral_id

    def get_user_info(self, uid: str) -> UserSessionInfo:
        usi = self.get([uid])
        if isinstance(usi, UserSessionInfo):
            return usi
        else:
            raise ValueError("Not UserSessionInfo")

    def find_token(self, session_id: str, token_value: str) -> Optional[Token]:
        """

        :param session_id: Based on 3-tuple, user_id, client_id and grant_id
        :param token_value:
        :return:
        """
        user_id, client_id, grant_id = unpack_session_key(session_id)
        grant = self.get([user_id, client_id, grant_id])
        for token in grant.issued_token:
            if token.value == token_value:
                return token

        return None

    def create_session(self, authn_event: AuthnEvent,
                       auth_req: AuthorizationRequest, user_id: str,
                       client_id: str = "",
                       sub_type: str = "public", sector_identifier: str = ''):
        """
        Create part of a user session. The parts added are user and client
        information. The missing part is the grant.

        :param authn_event:
        :param auth_req: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sector_identifier:
        :param sub_type:
        :return:
        """

        try:
            _ = self.get([user_id])
        except KeyError:
            user_info = UserSessionInfo(authentication_event=authn_event)
            self.set([user_id], user_info)

        client_info = ClientSessionInfo(
            authorization_request=auth_req,
            sub=self.sub_func[sub_type](user_id, salt=self.salt,
                                        sector_identifier=sector_identifier)
        )

        if not client_id:
            client_id = auth_req['client_id']

        self.set([user_id, client_id], client_info)

    def __getitem__(self, session_id: str):
        return self.get(unpack_session_key(session_id))

    def get_client_session_info(self, session_id: str) -> ClientSessionInfo:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        csi = self.get([_user_id, _client_id])
        if isinstance(csi, ClientSessionInfo):
            return csi
        else:
            raise ValueError("Wrong type of session info")

    def get_user_session_info(self, session_id: str) -> UserSessionInfo:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        usi = self.get([_user_id])
        if isinstance(usi, UserSessionInfo):
            return usi
        else:
            raise ValueError("Wrong type of session info")

    def get_grant(self, session_id: str) -> Grant:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        grant = self.get([_user_id, _client_id, _grant_id])
        if isinstance(grant, Grant):
            return grant
        else:
            raise ValueError("Wrong type of item")

    def _revoke_dependent(self, grant: Grant, token: Token):
        for t in grant.issued_token:
            if t.based_on == token.value:
                t.revoked = True
                self._revoke_dependent(grant, t)

    def revoke_token(self, session_id: str, token_value: str, recursive: bool = False):
        """
        Revoke a specific token that belongs to a specific user session.

        :param session_id: Session identifier
        :param token_value: Token value
        :param recursive: Revoke all tokens that was minted using this token or
            tokens minted by this token. Recursively.
        """
        token = self.find_token(session_id, token_value)
        if token is None:
            raise UnknownToken()

        token.revoked = True
        if recursive:
            grant = self[session_id]
            self._revoke_dependent(grant, token)

    def get_authentication_event(self, session_id: Optional[str] = "",
                                 user_id: Optional[str] = "") -> AuthnEvent:
        """
        Return the authentication event as a AuthnEvent instance coupled to a
        user session.

        :param session_id: A session identifier
        :return: None if no authentication event could be found or an AuthnEvent instance.
        """
        if user_id:
            _user_id = user_id
        elif session_id:
            _user_id = unpack_session_key(session_id)[0]
        else:
            raise AttributeError("Must have one of user_id or session_id")

        user_info = self.get([_user_id])

        return user_info["authentication_event"]

    def revoke_client_session(self, session_id: str):
        """
        Revokes a client session

        :param session_id: Session identifier
        """
        parts = unpack_session_key(session_id)
        if len(parts) == 2:
            _user_id, _client_id = parts
        elif len(parts) == 3:
            _user_id, _client_id, _ = parts
        else:
            raise ValueError("Invalid session ID")

        _info = self.get([_user_id, _client_id])
        self.set([_user_id, _client_id], _info.revoke())

    def revoke_grant(self, session_id: str):
        """
        Revokes the grant pointed to by a session identifier.

        :param session_id: A session identifier
        """
        _path = unpack_session_key(session_id)
        _info = self.get(_path)
        _info.revoke()
        self.set(_path, _info)

    def grants(self, session_id: str) -> List[Grant]:
        """
        Find all grant connected to a user session

        :param session_id: A session identifier
        :return: A list of grants
        """
        uid, cid, _gid = unpack_session_key(session_id)
        _csi = self.get([uid, cid])
        return [self.get([uid, cid, gid]) for gid in _csi['subordinate']]

    def get_session_info(self,
                         session_id: str,
                         user_session_info: bool = False,
                         client_session_info: bool = False,
                         grant: bool = False) -> dict:
        """
        Returns information connected to a session.

        :param session_id: The identifier of the session
        :param user_session_info: Whether user session info should part of the response
        :param client_session_info: Whether client session info should part of the response
        :param grant: Whether the grant should part of the response
        :return: A dictionary with session information
        """
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        res = {
            "session_id": session_id,
            "user_id": _user_id,
            "client_id": _client_id,
            "grant_id": _grant_id
        }
        if user_session_info:
            res["user_session_info"] = self.get([_user_id])
        if client_session_info:
            res["client_session_info"] = self.get([_user_id, _client_id])
        if grant:
            res["grant"] = self.get([_user_id, _client_id, _grant_id])

        return res

    def get_session_info_by_token(self,
                                  token_value: str,
                                  user_session_info: bool = False,
                                  client_session_info: bool = False,
                                  grant: bool = False) -> dict:
        _token_info = self.token_handler.info(token_value)
        return self.get_session_info(_token_info["sid"], user_session_info=user_session_info,
                                     client_session_info=client_session_info, grant=grant)

    def get_session_id_by_token(self, token_value: str) -> dict:
        _token_info = self.token_handler.info(token_value)
        return _token_info["sid"]

    def add_grant(self, user_id: str, client_id: str, **kwargs) -> Grant:
        """
        Creates and adds a grant to a user session.

        :param user_id: User identifier
        :param client_id: Client identifier
        :param kwargs: Keyword arguments to the Grant class initialization
        :return: A Grant instance
        """
        args = {k: v for k, v in kwargs.items() if k in Grant.attributes}
        _grant = Grant(**args)
        self.set([user_id, client_id, _grant.id], _grant)
        _client_session_info = self.get([user_id, client_id])
        _client_session_info["subordinate"].append(_grant.id)
        self.set([user_id, client_id], _client_session_info)
        return _grant

    @staticmethod
    def _pick_grant(client_info, token_type):
        if len(client_info["subordinate"]) == 1:
            return client_info["subordinate"][0]

        for grant in client_info["subordinate"]:
            match = 0
            for _token in grant.issued_token:
                for _class in token_type:
                    if isinstance(_token, _class):
                        match += 1
                        break
            if match == len(token_type):
                return grant
        return None

    def find_exchange_grant(self, token: str, resource_server: str) -> Optional[Grant]:
        session_info = self.get_session_info_by_token(token, client_session_info=True)
        c_info = session_info["client_session_info"]
        for grant_id in c_info["subordinate"]:
            grant = self.get([session_info['user_id'], session_info['client_id'], grant_id])
            if isinstance(grant, ExchangeGrant):
                if resource_server in grant.users:
                    return grant
        return None


def create_session_manager(endpoint_context, token_handler_args, db=None, sub_func=None):
    _token_handler = handler.factory(endpoint_context, **token_handler_args)
    return SessionManager(_token_handler, db=db, sub_func=sub_func)
