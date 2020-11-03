import hashlib
import logging

logger = logging.getLogger(__name__)


def db_key(*args):
    return ':'.join(args)


def unpack_db_key(key):
    return key.split(':')


def pairwise_id(uid, sector_identifier, salt, **kwargs):
    return hashlib.sha256(("%s%s%s" % (uid, sector_identifier, salt)).encode("utf-8")).hexdigest()


def public_id(uid, salt="", **kwargs):
    return hashlib.sha256("{}{}".format(uid, salt).encode("utf-8")).hexdigest()


class Info(object):
    def __init__(self, **kwargs):
        self._db = kwargs or {}
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


class UserInfo(Info):
    pass


class ClientInfo(Info):
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
                            self._db.set[_cid_key] = value
                    else:
                        _userinfo.add_subordinate(client_id)
                        if grant_id:
                            _cid_info = ClientInfo()
                            _cid_info.add_subordinate(grant_id)
                            self._db[_cid_key] = _cid_info
                            self._db[db_key(uid, client_id, grant_id)] = value
                        else:
                            _cid_info = ClientInfo()
                            self._db[_cid_key] = _cid_info
                        self._db[uid] = _userinfo
                else:
                    _userinfo.add_subordinate(client_id)
                    self._db[uid] = _userinfo
                    if grant_id:
                        _cid_info = ClientInfo()
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
                _user_info = UserInfo()
                _user_info.add_subordinate(client_id)
                if grant_id:
                    _cid_info = ClientInfo()
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
                if client_id in _dic['client_id']:
                    try:
                        _cinfo = self._db[db_key(uid, client_id)]
                    except KeyError:
                        pass
                    else:
                        if grant_id:
                            if grant_id in _cinfo['grant_id']:
                                self._db.__delitem__(db_key(uid, client_id, grant_id))
                        else:
                            self._db.__delitem__(db_key(uid, client_id))
                else:
                    pass
            else:
                self._db.__delitem__(uid)


class SessionManager(Database):
    def __init__(self, handler, storage=None):
        Database.__init__(self, storage)
        self.token_handler = handler

    def get_user(self, uid):
        user = self.get(uid)

    def find_grant(self, user_id, client_id, token_value):
        client_info = self.get([user_id, client_id])
        for grant_id in client_info["subordinate"]:
            grant = self.get([user_id, client_id, grant_id])
            for token in grant.issued_token:
                if token.value == token_value:
                    return grant, token

        return None
