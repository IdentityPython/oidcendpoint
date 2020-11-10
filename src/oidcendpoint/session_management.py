import hashlib
import logging

from oidcendpoint import rndstr
from oidcendpoint import token_handler
from oidcendpoint.token_handler import UnknownToken

logger = logging.getLogger(__name__)


class Revoked(Exception):
    pass


def db_key(*args):
    return ':'.join(args)


def unpack_db_key(key):
    return key.split(':')


def pairwise_id(uid, sector_identifier, salt="", **kwargs):
    return hashlib.sha256(("%s%s%s" % (uid, sector_identifier, salt)).encode("utf-8")).hexdigest()


def public_id(uid, salt="", **kwargs):
    return hashlib.sha256("{}{}".format(uid, salt).encode("utf-8")).hexdigest()


class SessionInfo(object):
    def __init__(self, **kwargs):
        self._db = kwargs or {}
        self._revoked = False
        if "subordinate" not in self._db:
            self._db["subordinate"] = []

    def set(self, key, value):
        self._db[key] = value

    def get(self, key):
        return self._db[key]

    def update(self, ava):
        self._db.update(ava)
        return self

    def add_subordinate(self, value):
        self._db["subordinate"].append(value)
        return self

    def remove_subordinate(self, value):
        self._db["subordinate"].remove(value)
        return self

    def __setitem__(self, key, value):
        self._db[key] = value

    def __getitem__(self, key):
        return self._db[key]

    def keys(self):
        return self._db.keys()

    def values(self):
        return self._db.values()

    def items(self):
        return self._db.items()

    def __contains__(self, item):
        return item in self._db

    def revoke(self):
        self._revoked = True

    def is_revoked(self):
        return self._revoked


class UserSessionInfo(SessionInfo):
    def __init__(self, **kwargs):
        SessionInfo.__init__(self, **kwargs)
        if "logout_sid" not in self._db:
            self._db["logout_sid"] = {}


class ClientSessionInfo(SessionInfo):
    def find_grant(self, val):
        for grant in self._db["subordinate"]:
            token = grant.get_token(val)
            if token:
                return grant, token


class Database(object):
    def __init__(self, storage=None):
        self._db = storage or {}

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
                    _cid_key = db_key(uid, client_id)
                    _cid_info = self._db[db_key(uid, client_id)]
                    if _cid_info.is_revoked():
                        raise Revoked("Session is revoked")
                    if _cid_info:
                        if grant_id:
                            _gid_key = db_key(uid, client_id, grant_id)
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
                            self._db[db_key(uid, client_id, grant_id)] = value
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
                        self._db[db_key(uid, client_id, grant_id)] = value
                    else:
                        _cid_info = value

                    _cid_key = db_key(uid, client_id)
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
                    self._db[db_key(uid, client_id, grant_id)] = value
                else:
                    _cid_info = value
                self._db[db_key(uid, client_id)] = _cid_info
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
                    client_session_info = self._db[db_key(uid, client_id)]
                except KeyError:
                    return {}
                else:
                    if client_session_info.is_revoked():
                        raise Revoked("Session is revoked")

                    if grant_id is None:
                        return client_session_info

                    if grant_id not in client_session_info['subordinate']:
                        raise ValueError('No such grant for that user and client')
                    else:
                        try:
                            return self._db[db_key(uid, client_id, grant_id)]
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
                        _cinfo = self._db[db_key(uid, client_id)]
                    except KeyError:
                        pass
                    else:
                        if grant_id:
                            if grant_id in _cinfo['subordinate']:
                                self._db.__delitem__(db_key(uid, client_id, grant_id))
                        else:
                            for grant_id in _cinfo['subordinate']:
                                self._db.__delitem__(db_key(uid, client_id, grant_id))
                            self._db.__delitem__(db_key(uid, client_id))

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
    def __init__(self, db, handler, sub_func=None):
        Database.__init__(self, db)
        self.token_handler = handler
        self.salt = rndstr(32)

        # this allows the subject identifier minters to be defined by someone
        # else then me.
        if sub_func is None:
            self.sub_func = {"public": public_id, "pairwise": pairwise_id}
        else:
            self.sub_func = sub_func
            if "public" not in sub_func:
                self.sub_func["public"] = public_id
            if "pairwise" not in sub_func:
                self.sub_func["pairwise"] = pairwise_id

    def get_user_info(self, uid):
        return self.get(uid)

    def find_token(self, session_id, token_value):
        """

        :param session_id: Based on 3-tuple, user_id, client_id and grant_id
        :param token_value:
        :return:
        """
        user_id, client_id, grant_id = unpack_db_key(session_id)
        grant = self.get([user_id, client_id, grant_id])
        for token in grant.issued_token:
            if token.value == token_value:
                return token

        return None

    def create_session(self, authn_event, auth_req, user_id, client_id="",
                       sub_type="public", sector_identifier='', **kwargs):
        """

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

    def _update_client_info(self, session_id, new_information):
        """

        :param session_id:
        :param new_information:
        :return:
        """
        _user_id, _client_id, _grant_id = unpack_db_key(session_id)
        _client_info = self.get([_user_id, _client_id])
        _client_info.update(new_information)
        self.set([_user_id, _client_id], _client_info)

    def do_sub(self, session_id, sector_id="", subject_type="public"):
        """
        Create and store a subject identifier

        :param session_id: Session ID
        :param sector_id: For pairwise identifiers, an Identifier for the RP group
        :param subject_type: 'pairwise'/'public'
        :return:
        """
        _user_id, _client_id, _grant_id = unpack_db_key(session_id)
        sub = self.sub_func[subject_type](_user_id, salt=self.salt, sector_identifier=sector_id)
        self._update_client_info(session_id, {'sub': sub})
        return sub

    def __getitem__(self, item):
        return self.get(unpack_db_key(item))

    def get_client_session_info(self, session_id):
        _user_id, _client_id, _grant_id = unpack_db_key(session_id)
        self.get([_user_id, _client_id])

    def _revoke_dependent(self, grant, token):
        for t in grant.issued_token:
            if t.based_on == token.value:
                t.revoked = True
                self._revoke_dependent(grant, t)

    def revoke_token(self, session_id, token_value, recursive=False):
        token = self.find_token(session_id, token_value)
        if token is None:
            raise UnknownToken()

        token.revoked = True
        if recursive:
            grant = self[session_id]
            self._revoke_dependent(grant, token)

    def get_sids_by_user_id(self, user_id):
        user_info = self.get([user_id])
        return [db_key(user_id, c) for c in user_info['subordinate']]

    def get_authentication_event(self, session_id):
        _user_id = unpack_db_key(session_id)[0]
        try:
            user_info = self.get([_user_id])
        except KeyError:
            return None

        return user_info["authentication_event"]

    def revoke_client_session(self, session_id):
        _user_id, _client_id, _ = unpack_db_key(session_id)
        _info = self.get([_user_id, _client_id])
        _info.revoke()
        self.set([_user_id, _client_id], _info)

    def revoke_grant(self, session_id):
        _path = unpack_db_key(session_id)
        _info = self.get(_path)
        _info.revoke()
        self.set(_path, _info)

    def grants(self, session_id):
        uid, cid, _gid = unpack_db_key(session_id)
        _csi = self.get([uid, cid])
        return [self.get([uid, cid, gid]) for gid in _csi['subordinate']]

    def get_session_info(self, session_id):
        _user_id, _client_id, _grant_id = unpack_db_key(session_id)
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


def create_session_manager(endpoint_context, token_handler_args, db=None, sub_func=None):
    _token_handler = token_handler.factory(endpoint_context, **token_handler_args)
    return SessionManager(db, _token_handler, sub_func=sub_func)
