import hashlib
import json
import logging
import uuid
from typing import List
from typing import Optional

from oidcmsg.oauth2 import AuthorizationRequest

from oidcendpoint import rndstr
from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.token import handler

from ..token import UnknownToken
from ..token.handler import TokenHandler
from . import session_key
from . import unpack_session_key
from .database import Database
from .grant import Grant
from .grant import Token
from .info import ClientSessionInfo
from .info import UserSessionInfo

logger = logging.getLogger(__name__)


def pairwise_id(uid, sector_identifier, salt="", **kwargs):
    return hashlib.sha256(("%s%s%s" % (uid, sector_identifier, salt)).encode("utf-8")).hexdigest()


def public_id(uid, salt="", **kwargs):
    return hashlib.sha256("{}{}".format(uid, salt).encode("utf-8")).hexdigest()


def ephemeral_id(*args, **kwargs):
    return uuid.uuid4().hex


class BaseSessionManager(Database):
    def __init__(self, handler: TokenHandler, db: Optional[object] = None,
                 conf: Optional[dict] = None, sub_func: Optional[dict] = None):
        Database.__init__(self, db)
        self.token_handler = handler
        self.salt = rndstr(32)
        self.conf = conf or {}

        self.load_sub_func(sub_func)

    def load_sub_func(self, sub_func):
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

    def create_grant(self,
                     authn_event: AuthnEvent,
                     auth_req: AuthorizationRequest,
                     user_id: str,
                     client_id: Optional[str] = "",
                     sub_type: Optional[str] = "public",
                     token_usage_rules: Optional[dict] = None,
                     scopes: Optional[list] = None
                     ) -> str:
        """

        :param scopes: Scopes
        :param authn_event: AuthnEvent instance
        :param auth_req:
        :param user_id:
        :param client_id:
        :param sub_type:
        :param token_usage_rules:
        :return:
        """
        try:
            sector_identifier = auth_req.get("sector_identifier_uri")
        except AttributeError:
            sector_identifier = ""

        grant = Grant(authorization_request=auth_req,
                      authentication_event=authn_event,
                      sub=self.sub_func[sub_type](
                          user_id, salt=self.salt,
                          sector_identifier=sector_identifier),
                      usage_rules=token_usage_rules,
                      scope=scopes
                      )

        self.set([user_id, client_id, grant.id], grant)

        return session_key(user_id, client_id, grant.id)

    def create_session(self,
                       authn_event: AuthnEvent,
                       auth_req: AuthorizationRequest,
                       user_id: str,
                       client_id: Optional[str] = "",
                       sub_type: Optional[str] = "public",
                       token_usage_rules: Optional[dict] = None,
                       scopes: Optional[list] = None
                       ) -> str:
        """
        Create part of a user session. The parts added are user- and client
        information and a grant.

        :param scopes:
        :param authn_event: Authentication Event information
        :param auth_req: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sector_identifier: Identifier for a group of websites under common administrative
            control.
        :param sub_type: What kind of subject will be assigned
        :param token_usage_rules: Rules for how tokens can be used
        :return: Session key
        """
        try:
            _usi = self.get([user_id])
        except KeyError:
            _usi = UserSessionInfo(user_id=user_id)
            self.set([user_id], _usi)

        if not client_id:
            client_id = auth_req['client_id']

        client_info = ClientSessionInfo(
            client_id=client_id,
        )

        self.set([user_id, client_id], client_info)

        return self.create_grant(
            auth_req=auth_req,
            authn_event=authn_event,
            user_id=user_id,
            client_id=client_id,
            sub_type=sub_type,
            token_usage_rules=token_usage_rules,
            scopes=scopes
        )

    def __getitem__(self, session_id: str):
        return self.get(unpack_session_key(session_id))

    def __setitem__(self, session_id: str, value):
        return self.set(unpack_session_key(session_id), value)

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

    def get_authentication_events(self, session_id: Optional[str] = "",
                                  user_id: Optional[str] = "",
                                  client_id: Optional[str] = "") -> List[AuthnEvent]:
        """
        Return the authentication events that exists for a user/client combination.

        :param session_id: A session identifier
        :return: None if no authentication event could be found or an AuthnEvent instance.
        """
        if session_id:
            user_id, client_id, _ = unpack_session_key(session_id)
        elif user_id and client_id:
            pass
        else:
            raise AttributeError("Must have session_id or user_id and client_id")

        c_info = self.get([user_id, client_id])

        _grants = [self.get([user_id, client_id, gid]) for gid in c_info['subordinate']]
        return [g.authentication_event for g in _grants]

    def get_authorization_request(self, session_id):
        res = self.get_session_info(session_id=session_id, authorization_request=True)
        return res["authorization_request"]

    def get_authentication_event(self, session_id):
        res = self.get_session_info(session_id=session_id, authentication_event=True)
        return res["authentication_event"]

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

    def grants(self,
               session_id: Optional[str] = "",
               user_id: Optional[str] = "",
               client_id: Optional[str] = "") -> List[Grant]:
        """
        Find all grant connected to a user session

        :param session_id: A session identifier
        :return: A list of grants
        """
        if session_id:
            user_id, client_id, _ = unpack_session_key(session_id)
        elif user_id and client_id:
            pass
        else:
            raise AttributeError("Must have session_id or user_id and client_id")

        _csi = self.get([user_id, client_id])
        return [self.get([user_id, client_id, gid]) for gid in _csi['subordinate']]

    def get_session_info(self,
                         session_id: str,
                         user_session_info: bool = False,
                         client_session_info: bool = False,
                         grant: bool = False,
                         authentication_event: bool = False,
                         authorization_request: bool = False) -> dict:
        """
        Returns information connected to a session.

        :param session_id: The identifier of the session
        :param user_session_info: Whether user session info should part of the response
        :param client_session_info: Whether client session info should part of the response
        :param grant: Whether the grant should part of the response
        :param authentication_event: Whether the authentication event information should part of
            the response
        :param authorization_request: Whether the authorization_request should part of the response
        :return: A dictionary with session information
        """
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        _grant = None
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

        if authentication_event:
            if grant:
                res["authentication_event"] = res["grant"]["authentication_event"]
            else:
                _grant = self.get([_user_id, _client_id, _grant_id])
                res["authentication_event"] = _grant.authentication_event

        if authorization_request:
            if grant:
                res["authorization_request"] = res["grant"].authorization_request
            elif _grant:
                res["authorization_request"] = _grant.authorization_request
            else:
                _grant = self.get([_user_id, _client_id, _grant_id])
                res["authorization_request"] = _grant.authorization_request

        return res

    def get_session_info_by_token(self,
                                  token_value: str,
                                  user_session_info: bool = False,
                                  client_session_info: bool = False,
                                  grant: bool = False,
                                  authentication_event: bool = False,
                                  authorization_request: bool = False
                                  ) -> dict:
        _token_info = self.token_handler.info(token_value)
        return self.get_session_info(_token_info["sid"],
                                     user_session_info=user_session_info,
                                     client_session_info=client_session_info,
                                     grant=grant,
                                     authentication_event=authentication_event,
                                     authorization_request=authorization_request)

    def get_session_id_by_token(self, token_value: str) -> str:
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

    # def find_grant_by_type_and_target(
    #         self,
    #         token: str,
    #         token_type: Grant,
    #         resource_server: str) -> Optional[Grant]:
    #     """
    #
    #     :param token:
    #     :param token_type:
    #     :param resource_server:
    #     :return:
    #     """
    #     session_id = self.get_session_id_by_token(token)
    #     for grant in self.grants(session_id=session_id):
    #         if isinstance(grant, token_type):
    #             if resource_server in grant.resources:
    #                 return grant
    #     return None

    def remove_session(self, session_id: str):
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        self.delete([_user_id, _client_id, _grant_id])


class SessionManager(BaseSessionManager):
    def __init__(self, handler: TokenHandler, db: Optional[object] = None,
                 conf: Optional[dict] = None, sub_func: Optional[dict] = None):
        self.token_handler = handler
        self.salt = rndstr(32)
        self.conf = conf or {}
        self.session_db = db.db # todo
        self.load_sub_func(sub_func)


    def create_grant(self,
                     authn_event: AuthnEvent,
                     auth_req: AuthorizationRequest,
                     oidc_session,
                     sub_type: Optional[str] = "public",
                     token_usage_rules: Optional[dict] = None,
                     scopes: Optional[list] = None
                     ) -> str:
        try:
            sector_identifier = auth_req.get("sector_identifier_uri", "")
        except AttributeError:
            sector_identifier = ""

        grant = Grant(authorization_request=auth_req,
                      authentication_event=authn_event,
                      sub=self.sub_func[sub_type](
                          oidc_session.user_uid,
                          salt=self.salt,
                          sector_identifier=sector_identifier),
                      usage_rules=token_usage_rules,
                      scope=scopes
                      )

        oidc_session.set_grant(grant)
        session_id = session_key(oidc_session.user_uid,
                                 oidc_session.client.client_id,
                                 grant.id)
        oidc_session.session_id = session_id
        oidc_session.save()
        return session_id


    def create_session(self,
                       authn_event: AuthnEvent,
                       auth_req: AuthorizationRequest,
                       user_id: str,
                       client_id: Optional[str] = "",
                       sub_type: Optional[str] = "public",
                       token_usage_rules: Optional[dict] = None,
                       scopes: Optional[list] = None
                       ) -> str:
        """
        Create part of a user session. The parts added are user- and client
        information and a grant.

        :param scopes:
        :param authn_event: Authentication Event information
        :param auth_req: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sector_identifier: Identifier for a group of websites under common administrative
            control.
        :param sub_type: What kind of subject will be assigned
        :param token_usage_rules: Rules for how tokens can be used
        :return: Session key
        """
        client_id = client_id or auth_req['client_id']

        data = {
                'user_uid' : user_id,
                'client_id' : client_id,
                'state': auth_req.get('state'),
                'authentication_event': authn_event.to_json(),
                'authentication_request': auth_req.to_json()
        }

        client_info = ClientSessionInfo(
            client_id=client_id,
        )

        user_session = self.session_db.get_session_by(**data)
        if not user_session:
            user_session_info = UserSessionInfo(user_id=user_id)
            data['user_session_info'] = user_session_info
            data['client_session_info'] = client_info
            user_session = self.session_db.create_by(**data)

        return self.create_grant(
            auth_req=auth_req,
            authn_event=authn_event,
            oidc_session=user_session,
            sub_type=sub_type,
            token_usage_rules=token_usage_rules,
            scopes=scopes
        )

    def get_grant(self, session_id: str) -> Grant:
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: ClientSessionInfo instance
        """
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        data = dict(user_uid = _user_id,
                    client_id = _client_id,
                    grant_id = _grant_id)
        session = self.session_db.get_by_session_id(**data)

        return session.json_to_dict('grant')


    def set(self, *args, **kwargs):
        """

        """
        if isinstance(args[1], dict) and args[1]['type'] == 'grant':
            data = dict(user_uid = args[0][0],
            client_id = args[0][1],
            grant_id = args[0][2])
            session = self.session_db.get_by_session_id(**data)
            session.grant = json.dumps(args[1])
            session.save()


    def get_session_info(self,
                         session_id: str,
                         user_session_info: bool = False,
                         client_session_info: bool = False,
                         grant: bool = False,
                         authentication_event: bool = False,
                         authorization_request: bool = False) -> dict:
        """
        Returns information connected to a session.

        :param session_id: The identifier of the session
        :param user_session_info: Whether user session info should part of the response
        :param client_session_info: Whether client session info should part of the response
        :param grant: Whether the grant should part of the response
        :param authentication_event: Whether the authentication event information should part of
            the response
        :param authorization_request: Whether the authorization_request should part of the response
        :return: A dictionary with session information
        """
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        _grant = None
        res = {
            "session_id": session_id,
            "user_id": _user_id,
            "client_id": _client_id,
            "grant_id": _grant_id
        }

        session = self.session_db.get_session_by(session_id = session_id)
        grant = session.json_to_dict('grant')

        if user_session_info:
            res["user_session_info"] = session.json_to_dict('user_session_info')

        if client_session_info:
            res["client_session_info"] = session.json_to_dict('client_session_info')

        if grant:
            res["grant"] = session.get_grant() # grant

        if authentication_event:
            res["authentication_event"] = session.get_authn_event()

        if authorization_request:
            res["authorization_request"] = session.json_to_dict('authorization_request')

        return res


    def find_token(self, session_id: str, token_value: str) -> Optional[Token]:
        """

        :param session_id: Based on 3-tuple, user_id, client_id and grant_id
        :param token_value:
        :return:
        """
        user_id, client_id, grant_id = unpack_session_key(session_id)
        data = dict(user_uid = user_id,
                    client_id = client_id,
                    grant_id = grant_id)
        session = self.session_db.get_by_session_id(**data)
        grant = session.get_grant()

        breakpoint()
        for token in grant.issued_token:
            if token.value == token_value:
                return token

        return None


def create_session_manager(endpoint_context, token_handler_args, db=None, sub_func=None):
    _token_handler = handler.factory(endpoint_context, **token_handler_args)
    return SessionManager(_token_handler, db=db, sub_func=sub_func)
