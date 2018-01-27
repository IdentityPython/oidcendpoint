import logging

logger = logging.getLogger(__name__)


class SSODb(object):
    """
    Keeps the connection between an user, one or more sub claims and
    possibly several session IDs.
    Each user can be represented by more then one sub claim and every sub claim
    can appear in more the one session.
    """
    def __init__(self, db=None):
        self._db = db or {}
        self._db['uid2sid'] = {}
        self._db['sid2uid'] = {}
        self._db['sub2sid'] = {}
        self._db['sid2sub'] = {}

    def map_sid2uid(self, sid, uid):
        """
        Store the connection between a Session ID and an uid.

        :param uid: subject ID
        :param sid: Session ID
        """
        try:
            self._db['uid2sid'][uid].append(sid)
        except KeyError:
            self._db['uid2sid'][uid] = [sid]

        self._db['sid2uid'][sid] = uid

    def get_sids_by_uid(self, uid):
        """
        Return a list of session IDs that this user is connected to.

        :param uid: The subject ID
        :return: list of session IDs
        """
        return self._db['uid2sid'][uid]

    def unmap_sid2uid(self, sid, uid):
        """
        Remove the connection between a session ID and a User ID.
        
        :param sid: Session ID 
        :param uid: User ID
        """
        self._db['uid2sid'][uid].remove(sid)

    def map_sid2sub(self, sid, sub):
        """
        Store the connection between a Session ID and a subject identifier
        
        :param sid: Session ID 
        :param sub: Subject identifier
        """
        try:
            self._db['sub2sid'][sub].append(sid)
        except KeyError:
            self._db['sub2sid'][sub] = [sid]
        self._db['sid2sub'][sid] = sub

    def get_sids_by_sub(self, sub):
        """
        Find all the Session IDs that are connected to this subject.
        
        :param sub: subject 
        :return: List of Session IDs
        """
        return self._db['sub2sid'][sub]

    def unmap_sid2sub(self, sid, sub):
        """
        Remove the connection between a session ID and a Subject
        
        :param sid: Session ID 
        :param sub: Subject identifier
´        """
        try:
            self._db['sub2sid'][sub].remove(sid)
        except KeyError:
            raise
        else:
            if not self._db['sub2sid'][sub]:
                del self._db['sub2sid'][sub]

        del self._db['sid2sub'][sid]

    def remove_session_id(self, sid):
        """
        Remove all references to a specific Session ID
        
        :param sid: A Session ID 
        """
        try:
            _uid = self._db['sid2uid'][sid]
        except KeyError:
            pass
        else:
            try:
                self._db['uid2sid'][_uid].remove(sid)
            except (KeyError, ValueError):
                pass

            try:
                del self._db['sid2uid'][sid]
            except KeyError:
                pass

        try:
            sub = self._db['sid2sub'][sid]
        except KeyError:
            pass
        else:
            try:
                self.unmap_sid2sub(sid, sub)
            except KeyError:
                pass

    def remove_uid(self, uid):
        """
        Remove all references to a specific User ID
        
        :param uid: A User ID 
        """
        for _sid in self._db['uid2sid'][uid]:
            del self._db['sid2uid'][_sid]

        del self._db['uid2sid'][uid]

    def get_uid_by_sid(self, sid):
        """
        Find the User ID that is connected to a Session ID.
        
        :param sid: A Session ID 
        :return: A User ID
        """
        return self._db['sid2uid'][sid]

    def uid2sub(self, uid):
        """
        Find all subject identifiers that is connected to a User ID.
        
        :param uid: A User ID 
        :return: A list of subject identifiers
        """
        res = []
        for sid in self._db['uid2sid'][uid]:
            res.append(self._db['sid2sub'][sid])
        return res
