from oidcendpoint.in_memory_db import InMemoryDataBase

KEY_FORMAT = '__{}__{}'


class SSODb(object):
    """
    Keeps the connection between an user, one or more sub claims and
    possibly several session IDs.
    Each user can be represented by more then one sub claim and every sub claim
    can appear in more the one session.
    So, we have chains like this:
        session id->subject id->user id
    """

    def __init__(self, db=None):
        self._db = db or InMemoryDataBase()

    def set(self, label, key, value):
        _key = KEY_FORMAT.format(label, key)
        _values = self._db.get(_key)
        if not _values:
            self._db.set(_key, [value])
        else:
            _values.append(value)
            self._db.set(_key, _values)

    def get(self, label, key):
        _key = KEY_FORMAT.format(label, key)
        return self._db.get(_key)

    def delete(self, label, key):
        _key = KEY_FORMAT.format(label, key)
        return self._db.delete(_key)

    def remove(self, label, key, value):
        _key = KEY_FORMAT.format(label, key)
        _values = self._db.get(_key)
        if _values:
            try:
                _values.remove(value)
            except ValueError:
                pass
            else:
                if _values:
                    self._db.set(_key, _values)
                else:
                    self._db.delete(_key)

    def map_sid2uid(self, sid, uid):
        """
        Store the connection between a Session ID and a User ID

        :param sid: Session ID
        :param uid: User ID
        """
        self.set('sid2uid', sid, uid)
        self.set('uid2sid', uid, sid)

    def map_sid2sub(self, sid, sub):
        """
        Store the connection between a Session ID and a subject ID.

        :param sid: Session ID
        :param sub: subject ID
        """
        self.set('sid2sub', sid, sub)
        self.set('sub2sid', sub, sid)

    def get_sids_by_uid(self, uid):
        """
        Return a list of session IDs that this user is connected to.

        :param uid: The subject ID
        :return: list of session IDs
        """
        return self.get('uid2sid', uid)

    def get_sids_by_sub(self, sub):
        return self.get('sub2sid', sub)

    def get_sub_by_sid(self, sid):
        _subs =self.get('sid2sub', sid)
        if _subs:
            return _subs[0]
        else:
            return None

    def get_uid_by_sid(self, sid):
        """
        Find the User ID that is connected to a Session ID.

        :param sid: A Session ID
        :return: A User ID, always just one
        """
        _uids = self.get('sid2uid', sid)
        if _uids:
            return _uids[0]
        else:
            return None

    def get_subs_by_uid(self, uid):
        """
        Find all subject identifiers that is connected to a User ID.

        :param uid: A User ID
        :return: A set of subject identifiers
        """
        res = set()
        for sid in self.get('uid2sid', uid):
            res |= set(self.get('sid2sub', sid))
        return res

    def remove_sid2sub(self, sid, sub):
        """
        Remove the connection between a session ID and a Subject

        :param sid: Session ID
        :param sub: Subject identifier
´        """
        self.remove('sub2sid', sub, sid)
        self.remove('sid2sub', sid, sub)

    def remove_sid2uid(self, sid, uid):
        """
        Remove the connection between a session ID and a Subject

        :param sid: Session ID
        :param uid: User identifier
´        """
        self.remove('uid2sid', uid, sid)
        self.remove('sid2uid', sid, uid)

    def remove_session_id(self, sid):
        """
        Remove all references to a specific Session ID

        :param sid: A Session ID
        """
        for uid in self.get('sid2uid', sid):
            self.remove('uid2sid', uid, sid)
        self.delete('sid2uid', sid)

        for sub in self.get('sid2sub', sid):
            self.remove('sub2sid', sub, sid)
        self.delete('sid2sub', sid)

    def remove_uid(self, uid):
        """
        Remove all references to a specific User ID

        :param uid: A User ID
        """
        for sid in self.get('uid2sid', uid):
            self.remove('sid2uid', sid, uid)
        self.delete('uid2sid', uid)

    def remove_sub(self, sub):
        """
        Remove all references to a specific Subject ID

        :param sub: A Subject ID
        """
        for _sid in self.get('sub2sid', sub):
            self.remove('sid2sub', _sid, sub)
        self.delete('sub2sid', sub)
