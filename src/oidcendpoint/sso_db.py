import logging

logger = logging.getLogger(__name__)


class Map(object):
    def __init__(self, db=None):
        self._db = db or {}

    def __getitem__(self, item):
        return self._db[item]

    def __setitem__(self, key, value):
        try:
            self._db[key].append(value)
        except KeyError:
            self._db[key] = [value]

    def keys(self):
        return self._db.keys()

    def __delitem__(self, key):
        del self._db[key]

    def delete(self, key, value):
        self._db[key].remove(value)
        if len(self._db[key]) == 0:
            del self._db[key]

    def add(self, key, value):
        try:
            self._db[key].append(value)
        except KeyError:
            self._db[key] = [value]


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
        self._db = db or {}
        self._db = {
            'uid2sid': {}, 'sid2uid': {},
            'sub2sid': {}, 'sid2sub': {}
        }

        self.uid2sid = Map(self._db['uid2sid'])
        self.uid2sid_rev = Map(self._db['sid2uid'])

        self.sub2sid = Map(self._db['sub2sid'])
        self.sub2sid_rev = Map(self._db['sid2sub'])

    def map_sid2uid(self, sid, uid):
        """
        Store the connection between a Session ID and an uid.

        :param uid: subject ID
        :param sid: Session ID
        """
        self.uid2sid.add(uid, sid)
        self.uid2sid_rev.add(sid, uid)

    def get_sids_by_uid(self, uid):
        """
        Return a list of session IDs that this user is connected to.

        :param uid: The subject ID
        :return: list of session IDs
        """
        return self.uid2sid[uid]

    def unmap_sid2uid(self, sid, uid):
        """
        Remove the connection between a session ID and a User ID.
        
        :param sid: Session ID 
        :param uid: User ID
        """
        self.uid2sid.delete(uid, sid)
        self.uid2sid_rev.delete(sid, uid)

    def map_sid2sub(self, sid, sub):
        """
        Store the connection between a Session ID and a subject identifier
        
        :param sid: Session ID 
        :param sub: Subject identifier
        """
        self.sub2sid.add(sub, sid)
        self.sub2sid_rev.add(sid, sub)

    def get_sids_by_sub(self, sub):
        """
        Find all the Session IDs that are connected to this subject.
        
        :param sub: subject 
        :return: List of Session IDs
        """
        return self.sub2sid[sub]

    def unmap_sid2sub(self, sid, sub):
        """
        Remove the connection between a session ID and a Subject
        
        :param sid: Session ID 
        :param sub: Subject identifier
´        """
        self.sub2sid.delete(sub, sid)
        if len(self.sub2sid[sub]) == 0:
            del self.sub2sid[sub]

        self.sub2sid_rev[sid].append(sub)
        if len(self.sub2sid_rev[sid]) == 0:
            del self.sub2sid_rev[sid]

    def remove_session_id(self, sid):
        """
        Remove all references to a specific Session ID
        
        :param sid: A Session ID 
        """
        try:
            _uid = self.uid2sid_rev[sid]
        except KeyError:
            pass
        else:
            try:
                self.uid2sid.delete(_uid, sid)
            except (KeyError, ValueError):
                pass

        try:
            sub = self.sub2sid_rev[sid]
        except KeyError:
            pass
        else:
            try:
                self.sub2sid.delete(sub, sid)
            except KeyError:
                pass

    def remove_uid(self, uid):
        """
        Remove all references to a specific User ID
        
        :param uid: A User ID 
        """

        for _sid in self.uid2sid[uid]:
            self.uid2sid_rev.delete(_sid, uid)

        del self.uid2sid[uid]

    def remove_sub(self, sub):
        """
        Remove all references to a specific Subject ID

        :param sub: A Subject ID
        """
        for _sid in self.sub2sid[sub]:
            self.sub2sid_rev.delete(_sid, sub)
        del self.sub2sid[sub]

    def get_uid_by_sid(self, sid):
        """
        Find the User ID that is connected to a Session ID.
        
        :param sid: A Session ID 
        :return: A User ID, always just one
        """
        return self.uid2sid_rev[sid][0]

    def get_sub_by_uid(self, uid):
        """
        Find all subject identifiers that is connected to a User ID.
        
        :param uid: A User ID 
        :return: A set of subject identifiers
        """
        res = set()
        for sid in self.uid2sid[uid]:
            res |= set(self.sub2sid_rev[sid])
        return res
