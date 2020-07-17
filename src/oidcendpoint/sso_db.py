import logging

from oidcmsg.storage.init import storage_factory

logger = logging.getLogger(__name__)


class DictDatabase:
    def __init__(self, db_conf=None, db=None):
        if db_conf:
            self._db = storage_factory(db_conf)
        else:
            self._db = db

    def set(self, key, sec_key, value):
        logger.debug("SSODb set {} - {}: {}".format(key, sec_key, value))
        # Try loading the key
        _dic = self._db.get(key, {})
        if sec_key in _dic:
            _dic[sec_key].append(value)
        else:
            _dic[sec_key] = [value]
        self._db[key] = _dic

    def get(self, key, sec_key):
        _dic = self._db.get(key, {})
        logger.debug("SSODb get {} - {}: {}".format(key, sec_key, _dic))
        return _dic.get(sec_key, None)

    def delete(self, key, sec_key):
        _dic = self._db.get(key, {})
        del _dic[sec_key]
        if _dic == {}:
            del self._db[key]
        else:
            self._db[key] = _dic

    def remove(self, key, sec_key, value):
        _dic = self._db.get(key, {})
        _values = _dic[sec_key]
        # full clean up
        while value in _values:
            _values.remove(value)
        # if changes have been made -> update them

        if _values:
            _dic[sec_key] = _values
            self._db[key] = _dic
        else:
            del _dic[sec_key]
            self._db[key] = _dic


class SSODb(DictDatabase):
    """
    Keeps the connection between an user, one or more sub claims and
    possibly several session IDs.
    Each user can be represented by more then one sub claim and every sub claim
    can appear in more the one session.
    So, we have chains like this::

        session id->subject id->user id

    """

    def map_sid2uid(self, sid, uid):
        """
        Store the connection between a Session ID and a User ID

        :param sid: Session ID
        :param uid: User ID
        """
        self.set(sid, "uid", uid)
        self.set(uid, "sid", sid)

    def map_sid2sub(self, sid, sub):
        """
        Store the connection between a Session ID and a subject ID.

        :param sid: Session ID
        :param sub: subject ID
        """
        self.set(sid, "sub", sub)
        self.set(sub, "sid", sid)

    def get_sids_by_uid(self, uid):
        """
        Return a list of session IDs that this user is connected to.

        :param uid: The subject ID
        :return: list of session IDs
        """
        return self.get(uid, "sid")

    def get_sids_by_sub(self, sub):
        return self.get(sub, "sid")

    def get_sub_by_sid(self, sid):
        _subs = self.get(sid, "sub")
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
        _uids = self.get(sid, "uid")
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
        for sid in self.get(uid, "sid"):
            res |= set(self.get(sid, "sub"))
        return res

    def remove_sid2sub(self, sid, sub):
        """
        Remove the connection between a session ID and a Subject

        :param sid: Session ID
        :param sub: Subject identifier
´       """
        self.remove(sub, "sid", sid)
        self.remove(sid, "sub", sub)

    def remove_sid2uid(self, sid, uid):
        """
        Remove the connection between a session ID and a Subject

        :param sid: Session ID
        :param uid: User identifier
´       """
        self.remove(uid, "sid", sid)
        self.remove(sid, "uid", uid)

    def remove_session_id(self, sid):
        """
        Remove all references to a specific Session ID

        :param sid: A Session ID
        """
        for uid in self.get(sid, "uid"):
            self.remove(uid, "sid", sid)
            if self._db.get(uid) == {}:
                del self._db[uid]
        self.delete(sid, "uid")

        for sub in self.get(sid, "sub"):
            self.remove(sub, "sid", sid)
            if self._db.get(sub) == {}:
                del self._db[sub]
        self.delete(sid, "sub")

    def remove_uid(self, uid):
        """
        Remove all references to a specific User ID

        :param uid: A User ID
        """
        for sid in self.get(uid, "sid"):
            self.remove(sid, "uid", uid)
        self.delete(uid, "sid")

    def remove_sub(self, sub):
        """
        Remove all references to a specific Subject ID

        :param sub: A Subject ID
        """
        for _sid in self.get(sub, "sid"):
            self.remove(_sid, "sub", sub)
        self.delete(sub, "sid")

    def close(self):
        self._db.close()

    def clear(self):
        self._db.clear()
