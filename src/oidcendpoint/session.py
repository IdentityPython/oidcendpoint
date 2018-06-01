import hashlib
import json

from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING

from oidcendpoint import rndstr
from oidcendpoint.authn_event import AuthnEvent


class SessionInfo(Message):
    c_param = {
        'oauth_state': SINGLE_REQUIRED_STRING,
        'code': SINGLE_OPTIONAL_STRING,
        'authn_req': SINGLE_REQUIRED_STRING,
        'client_id': SINGLE_REQUIRED_STRING,
        'authn_event': SINGLE_REQUIRED_STRING,
        'si_redirects': OPTIONAL_LIST_OF_STRINGS,
        'oidc_req': SINGLE_OPTIONAL_STRING
        }


def pairwise_id(sub, sector_identifier, seed):
    return hashlib.sha256(
        ("%s%s%s" % (sub, sector_identifier, seed)).encode("utf-8")).hexdigest()


def mint_sub(authn_event, client_salt, sector_id="", subject_type="public"):
    """
    Mint a new sub (subject identifier)

    :param authn_event: Authentication event information
    :param client_salt: client specific salt - used in pairwise
    :param sector_id: Possible sector identifier
    :param subject_type: 'public'/'pairwise'
    :return: Subject identifier
    """
    uid = authn_event['uid']
    user_salt = authn_event['salt']

    if subject_type == "public":
        sub = hashlib.sha256(
            "{}{}".format(uid, user_salt).encode("utf-8")).hexdigest()
    else:
        sub = pairwise_id(uid, sector_id,
                          "{}{}".format(client_salt, user_salt))
    return sub


class SessionDB(object):
    def __init__(self, db, handler, sso_db):
        # db must implement the InMemoryStateDataBase interface
        self._db = db
        self.handler = handler
        self.sso_db = sso_db

    def __getitem__(self, sid):
        _info = self._db.get(sid)
        _si = SessionInfo().from_json(_info)
        return _si

    def __setitem__(self, sid, instance):
        try:
            _info = instance.to_json()
        except ValueError:
            _info = json.dumps(instance)
        self._db.set(sid, _info)

    def __delitem__(self, key):
        self._db.delete(key)

    def create_authz_session(self, client_id, authn_event, areq,
                             oidc_req=None):
        key = rndstr(48)
        _info = SessionInfo(client_id=client_id)

        try:
            _info['authn_req'] = areq.to_json()
        except AttributeError:
            _info['authn_req'] = json.dumps(areq)

        _info['authn_event'] = authn_event.to_json()

        if oidc_req:
            _info['oidc_req'] = oidc_req.to_json()

        self[key] = _info.to_json()
        return key

    def update(self, sid, **kwargs):
        """
        Add attribute value assertion to a special session

        :param sid: Session ID
        :param kwargs:
        """
        item = self[sid]
        for attribute, value in kwargs.items():
            item[attribute] = value
        self[sid] = item

    def update_by_token(self, token, **kwargs):
        """
        Updated the session info. Any type of known token can be used

        :param token: code/access token/refresh token/...
        :param kwargs: Key word arguements
        """
        _sid = self.handler.sid(token)
        return self.update(_sid, **kwargs)

    def get_authentication_event(self, sid):
        return AuthnEvent().from_json(self[sid]["authn_event"])

    def get_token(self, sid):
        _sess_info = self[sid]

        if _sess_info['oauth_state'] == "authz":
            return _sess_info["code"]
        elif _sess_info["oauth_state"] == "token":
            return _sess_info["access_token"]

    def do_sub(self, sid, client_salt, sector_id='', subject_type='public'):
        authn_event = self.get_authentication_event(sid)
        sub = mint_sub(authn_event, client_salt, sector_id, subject_type)

        self.sso_db.map_sid2uid(sid, authn_event['uid'])
        self.update(sid, sub=sub)
        self.sso_db.map_sid2sub(sid, sub)

        return sub