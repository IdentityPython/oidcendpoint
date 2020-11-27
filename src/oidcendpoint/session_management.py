import hashlib
import logging
import uuid

from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import OPTIONAL_MESSAGE
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_BOOLEAN
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import list_deserializer
from oidcmsg.message import list_serializer

from oidcendpoint import rndstr
from oidcendpoint import token_handler
from oidcendpoint.grant import AccessToken
from oidcendpoint.grant import AuthorizationCode
from oidcendpoint.grant import Grant
from oidcendpoint.token_handler import UnknownToken

logger = logging.getLogger(__name__)


class Revoked(Exception):
    pass


def session_key(*args):
    return ':'.join(args)


def unpack_session_key(key):
    return key.split(':')


def pairwise_id(uid, sector_identifier, salt="", **kwargs):
    return hashlib.sha256(("%s%s%s" % (uid, sector_identifier, salt)).encode("utf-8")).hexdigest()


def public_id(uid, salt="", **kwargs):
    return hashlib.sha256("{}{}".format(uid, salt).encode("utf-8")).hexdigest()


def ephemeral_id(uid, **kwargs):
    return uuid.uuid4().hex


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

    def add_subordinate(self, value):
        self["subordinate"].append(value)
        return self

    def remove_subordinate(self, value):
        self["subordinate"].remove(value)
        return self

    def revoke(self):
        self["revoked"] = True
        return self

    def is_revoked(self):
        return self["revoked"]


class UserSessionInfo(SessionInfo):
    c_param = SessionInfo.c_param.copy()
    c_param.update({
        "authentication_event": OPTIONAL_MESSAGE,
    })

    def __init__(self, **kwargs):
        SessionInfo.__init__(self, **kwargs)
        self["type"] = "UserSessionInfo"


class ClientSessionInfo(SessionInfo):
    c_param = SessionInfo.c_param.copy()
    c_param.update({
        "authorization_request": OPTIONAL_MESSAGE,
        "sub": SINGLE_OPTIONAL_STRING
    })

    def __init__(self, **kwargs):
        SessionInfo.__init__(self, **kwargs)
        self["type"] = "ClientSessionInfo"

    def find_grant(self, val):
        for grant in self["subordinate"]:
            token = grant.get_token(val)
            if token:
                return grant, token


class Database(object):
    def __init__(self, storage=None):
        if storage is None:
            self._db = {}
        else:
            self._db = storage

    def eval_path(self, path):
        uid = path[0]
        client_id = None
        grant_id = None
        if len(path) > 1:
            client_id = path[1]
            if len(path) > 2:
                grant_id = path[2]

        return uid, client_id, grant_id

    def set(self, path: list, value: object):
        """

        :param path: a list of identifiers
        :param value: Class instance to be stored
        """
        # Try loading the key, that's a good place to put a debugger to
        #  import pdb; pdb.set_trace()
        uid, client_id, grant_id = self.eval_path(path)

        _userinfo = self._db.get(uid)
        if _userinfo:
            if client_id:
                if client_id in _userinfo['subordinate']:
                    _cid_key = session_key(uid, client_id)
                    _cid_info = self._db[session_key(uid, client_id)]
                    # if _cid_info.is_revoked():
                    #     raise Revoked("Session is revoked")
                    if _cid_info:
                        if grant_id:
                            _gid_key = session_key(uid, client_id, grant_id)
                            if grant_id in _cid_info['subordinate']:
                                _gid_info = self._db[_gid_key]
                                if not _gid_info:
                                    self._db[_cid_key] = _cid_info.add_subordinate(grant_id)
                                self._db[_gid_key] = value
                            else:
                                self._db[_cid_key] = _cid_info.add_subordinate(grant_id)
                                self._db[_gid_key] = value
                        else:
                            self._db[_cid_key] = value
                    else:
                        _userinfo.add_subordinate(client_id)
                        if grant_id:
                            _cid_info = ClientSessionInfo()
                            _cid_info.add_subordinate(grant_id)
                            self._db[_cid_key] = _cid_info
                            self._db[session_key(uid, client_id, grant_id)] = value
                        else:
                            _cid_info = ClientSessionInfo()
                            self._db[_cid_key] = _cid_info
                        self._db[uid] = _userinfo
                else:
                    _userinfo.add_subordinate(client_id)
                    self._db[uid] = _userinfo
                    if grant_id:
                        _cid_info = ClientSessionInfo()
                        _cid_info.add_subordinate(grant_id)
                        self._db[session_key(uid, client_id, grant_id)] = value
                    else:
                        _cid_info = value

                    _cid_key = session_key(uid, client_id)
                    self._db[_cid_key] = _cid_info
            else:
                self._db[uid] = value
        else:
            if client_id:
                _user_info = UserSessionInfo()
                _user_info.add_subordinate(client_id)
                if grant_id:
                    _cid_info = ClientSessionInfo()
                    _cid_info.add_subordinate(grant_id)
                    self._db[session_key(uid, client_id, grant_id)] = value
                else:
                    _cid_info = value
                self._db[session_key(uid, client_id)] = _cid_info
            else:
                _user_info = value

            self._db[uid] = _user_info

    def get(self, path: list):
        uid, client_id, grant_id = self.eval_path(path)
        try:
            user_info = self._db[uid]
        except KeyError:
            raise KeyError('No such UserID')
        else:
            if user_info is None:
                raise KeyError('No such UserID')

        if client_id is None:
            return user_info
        else:
            if client_id not in user_info['subordinate']:
                raise ValueError('No session from that client for that user')
            else:
                try:
                    client_session_info = self._db[session_key(uid, client_id)]
                except KeyError:
                    return {}
                else:
                    # if client_session_info.is_revoked():
                    #     raise Revoked("Session is revoked")

                    if grant_id is None:
                        return client_session_info

                    if grant_id not in client_session_info['subordinate']:
                        raise ValueError('No such grant for that user and client')
                    else:
                        try:
                            return self._db[session_key(uid, client_id, grant_id)]
                        except KeyError:
                            return {}

    def delete(self, path):
        uid, client_id, grant_id = self.eval_path(path)
        try:
            _dic = self._db[uid]
        except KeyError:
            pass
        else:
            if client_id:
                if client_id in _dic['subordinate']:
                    try:
                        _cinfo = self._db[session_key(uid, client_id)]
                    except KeyError:
                        pass
                    else:
                        if grant_id:
                            if grant_id in _cinfo['subordinate']:
                                self._db.__delitem__(session_key(uid, client_id, grant_id))
                        else:
                            for grant_id in _cinfo['subordinate']:
                                self._db.__delitem__(session_key(uid, client_id, grant_id))
                            self._db.__delitem__(session_key(uid, client_id))

                    _dic["subordinate"].remove(client_id)
                    self._db[uid] = _dic
                else:
                    pass
            else:
                self._db.__delitem__(uid)

    def update(self, path, new_info):
        _info = self.get(path)
        _info.update(new_info)
        self.set(path, _info)


class SessionManager(Database):
    def __init__(self, db, handler, conf=None, sub_func=None):
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

    def get_user_info(self, uid):
        return self.get(uid)

    def find_token(self, session_id, token_value):
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

    def create_session(self, authn_event, auth_req, user_id, client_id="",
                       sub_type="public", sector_identifier='', **kwargs):
        """
        Create part of a user session. The parts added are user and client
        information. The missing part is the grant.

        :param authn_event:
        :param auth_req: Authorization Request
        :param client_id: Client ID
        :param user_id: User ID
        :param sector_identifier:
        :param sub_type:
        :param kwargs: extra keyword arguments
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

    def __getitem__(self, item):
        return self.get(unpack_session_key(item))

    def get_client_session_info(self, session_id):
        """
        Return client connected information for a user session.

        :param session_id: Session identifier
        :return: UserSessionInfo instance
        """
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        return self.get([_user_id, _client_id])

    def _revoke_dependent(self, grant, token):
        for t in grant.issued_token:
            if t.based_on == token.value:
                t.revoked = True
                self._revoke_dependent(grant, t)

    def revoke_token(self, session_id, token_value, recursive=False):
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

    def get_sids_by_user_id(self, user_id):
        """
        Find and return all session identifiers for a user.

        :param user_id: User identifier
        :return: Possibly empty list of session identifiers
        """
        user_info = self.get([user_id])
        return [session_key(user_id, c) for c in user_info['subordinate']]

    def get_authentication_event(self, session_id):
        """
        Return the authentication event as a AuthnEvent instance coupled to a
        user session.

        :param session_id: A session identifier
        :return: None if no authentication event could be found or an AuthnEvent instance.
        """
        _user_id = unpack_session_key(session_id)[0]
        try:
            user_info = self.get([_user_id])
        except KeyError:
            return None

        return user_info["authentication_event"]

    def revoke_client_session(self, session_id):
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

    def revoke_grant(self, session_id):
        """
        Revokes the grant pointed to by a session identifier.

        :param session_id: A session identifier
        """
        _path = unpack_session_key(session_id)
        _info = self.get(_path)
        _info.revoke()
        self.set(_path, _info)

    def grants(self, session_id):
        """
        Find all grant connected to a user session

        :param session_id: A session identifier
        :return: A list of grants
        """
        uid, cid, _gid = unpack_session_key(session_id)
        _csi = self.get([uid, cid])
        return [self.get([uid, cid, gid]) for gid in _csi['subordinate']]

    def get_session_info(self, session_id):
        _user_id, _client_id, _grant_id = unpack_session_key(session_id)
        return {
            "session_id": session_id,
            "user_id": _user_id,
            "client_id": _client_id,
            "user_session_info": self.get([_user_id]),
            "client_session_info": self.get([_user_id, _client_id]),
            "grant": self.get([_user_id, _client_id, _grant_id])
        }

    def get_session_info_by_token(self, token_value):
        _token_info = self.token_handler.info(token_value)
        return self.get_session_info(_token_info["sid"])

    def add_grant(self, user_id, client_id, **kwargs):
        """
        Creates and adds a grant to a user session.

        :param user_id: User identifier
        :param client_id: Client identifier
        :param kwargs: Keyword arguments to the Grant class initialization
        :return: A Grant instance
        """
        args = {k: v for k, v in kwargs.items() if k in Grant.parameters}
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

    def get_grant_by_response_type(self, user_id, client_id):
        _client_info = self.get([user_id, client_id])
        response_type = _client_info["authorization_request"]["response_type"]
        if response_type == ["code"]:
            return self._pick_grant(_client_info, [AuthorizationCode])
        elif response_type == ["token"] or response_type == ["token", "id_token"]:
            return self._pick_grant(_client_info, [AccessToken])
        elif response_type == ["id_token"]:
            for grant in _client_info["subordinate"]:
                if not grant.issued_token:
                    return grant
        elif response_type == ["code", "token"] or response_type == ["code", "token", "id_token"]:
            return self._pick_grant(_client_info, [AuthorizationCode, AccessToken])

        return None


def create_session_manager(endpoint_context, token_handler_args, db=None, sub_func=None):
    _token_handler = token_handler.factory(endpoint_context, **token_handler_args)
    return SessionManager(db, _token_handler, sub_func=sub_func)
