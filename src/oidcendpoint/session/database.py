import logging
from typing import List
from typing import Union

from . import session_key
from .grant import Grant
from .info import ClientSessionInfo
from .info import SessionInfo
from .info import UserSessionInfo

logger = logging.getLogger(__name__)


class Database(object):
    def __init__(self, storage=None):
        if storage is None:
            self._db = {}
        else:
            self._db = storage

    @staticmethod
    def _eval_path(path: List[str]):
        uid = path[0]
        client_id = None
        grant_id = None
        if len(path) > 1:
            client_id = path[1]
            if len(path) > 2:
                grant_id = path[2]

        return uid, client_id, grant_id

    def set(self, path: List[str], value: Union[SessionInfo, Grant]):
        """

        :param path: a list of identifiers
        :param value: Class instance to be stored
        """
        # Try loading the key, that's a good place to put a debugger to
        #  import pdb; pdb.set_trace()
        uid, client_id, grant_id = self._eval_path(path)

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

    def get(self, path: List[str]) -> Union[SessionInfo, Grant]:
        uid, client_id, grant_id = self._eval_path(path)
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
                    return SessionInfo()
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
                            return SessionInfo()

    def delete(self, path: List[str]):
        uid, client_id, grant_id = self._eval_path(path)
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

    def update(self, path: List[str], new_info: dict):
        _info = self.get(path)
        for key, val in new_info.items():
            _info[key] = val
        self.set(path, _info)
