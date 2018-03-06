import copy
import hashlib
import logging
import time

from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import time_sans_frac

from oidcendpoint.sso_db import SSODb
from oidcendpoint.token_handler import ExpiredToken
from oidcendpoint.token_handler import is_expired
from oidcendpoint.token_handler import UnknownToken
from oidcendpoint.token_handler import AccessCodeUsed
from oidcendpoint.token_handler import DefaultToken
from oidcendpoint.token_handler import WrongTokenType
from oidcendpoint.token_handler import TokenHandler

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)


def pairwise_id(sub, sector_identifier, seed):
    return hashlib.sha256(
        ("%s%s%s" % (sub, sector_identifier, seed)).encode("utf-8")).hexdigest()


def dict_match(a, b):
    res = []
    for k, v in a.items():
        try:
            res.append(b[k] == v)
        except KeyError:
            pass
    return all(res)


class AuthnEvent(object):
    def __init__(self, uid, salt, valid=3600, authn_info=None,
                 time_stamp=0, authn_time=None, valid_until=None):
        """
        Creates a representation of an authentication event.

        :param uid: The local user identifier
        :param salt: Salt to be used in creating a sub
        :param valid: How long the authentication is expected to be valid
        :param authn_info: Info about the authentication event
        :return:
        """
        self.uid = uid
        self.salt = salt
        self.authn_time = authn_time or (int(time_stamp) or time_sans_frac())
        self.valid_until = valid_until or (self.authn_time + int(valid))
        self.authn_info = authn_info

    def __getitem__(self, item):
        return getattr(self, item)

    def valid(self):
        return self.valid_until > time.time()

    def valid_for(self):
        return self.valid_until - time.time()

    def to_json(self):
        return self.__dict__

    def to_dict(self):
        return self.__dict__


def create_session_db(issuer, password, db=None,
                      token_expires_in=3600, grant_expires_in=600,
                      refresh_token_expires_in=86400, sso_db=None):
    """
    Convenience wrapper for SessionDB construction

    Using this you can create a very basic non persistant
    session database that issues opaque DefaultTokens.

    :param issuer: Same as issuer parameter of `SessionDB`
    :param password: Secret key to pass to `DefaultToken` class.
    :param db: Storage for the session data, usually a dict.
    :param token_expires_in: Expiry time for access tokens in seconds.
    :param grant_expires_in: Expiry time for access codes in seconds.
    :param refresh_token_expires_in: Expiry time for refresh tokens.

    :return: A constructed `SessionDB` object.
    """

    code_handler = DefaultToken(password, typ='A',
                                lifetime=grant_expires_in)
    access_token_handler = DefaultToken(password, typ='T',
                                        lifetime=token_expires_in)
    refresh_token_handler = DefaultToken(password, typ='R',
                                         lifetime=refresh_token_expires_in)

    db = {} if db is None else db
    sso_db = SSODb() if sso_db is None else sso_db

    handler = TokenHandler(
        code_handler=code_handler,
        access_token_handler=access_token_handler,
        refresh_token_handler=refresh_token_handler,
    )

    return SessionDB(issuer, db, handler=handler, sso_db=sso_db)


class SessionDB(object):
    def __init__(self, issuer, db, handler, sso_db):

        self.issuer = issuer
        self._db = db
        self.handler = handler
        self.sso_db = sso_db

    def __getitem__(self, item):
        """
        :param item: authz grant code or refresh token
        """
        try:
            # First guess it's a session ID
            return self._db[item]
        except KeyError:
            # Was not, so then it can be a code, access token or refresh token
            # Map such an item against a session ID
            sid = self.handler.sid(item)
            return self._db[sid]

    def __setitem__(self, key, value):
        """
        :param key: authz grant code or refresh token
        """

        self._db[key] = value

    def __delitem__(self, sid):
        """
        Actually delete the pointed session from this SessionDB instance

        :param sid: session identifier
        """
        del self._db[sid]

    def is_valid(self, item):
        try:
            return not self.handler.is_black_listed(item)
        except KeyError:
            return False

    def get_sids_by_sub(self, sub):
        return self.sso_db.get_sids_by_sub(sub)

    def update(self, sid, **kwargs):
        """
        Add attribute value assertion to a special session

        :param sid: Session ID
        :param attribute:
        :param value:
        :return:
        """
        item = self._db[sid]
        for attribute, value in kwargs.items():
            item[attribute] = value
        self._db[sid] = item

    def update_by_token(self, token, **kwargs):
        """
        Updated the session info. Any type of known token can be used
        
        :param token: code/access token/refresh token/... 
        :param attribute: The attribute name
        :param value: The attribute value
        """
        _sid = self.handler.sid(token)
        return self.update(_sid, **kwargs)

    def do_sub(self, sid, client_salt, sector_id="", subject_type="public"):
        """
        Construct a sub (subject identifier)

        :param sid: Session identifier
        :param sector_id: Possible sector identifier
        :param subject_type: 'public'/'pairwise'
        :param client_salt: client specific salt - used in pairwise
        :return:
        """
        uid = self._db[sid]["authn_event"].uid
        user_salt = self._db[sid]["authn_event"].salt

        if subject_type == "public":
            sub = hashlib.sha256(
                "{}{}".format(uid, user_salt).encode("utf-8")).hexdigest()
        else:
            sub = pairwise_id(uid, sector_id,
                              "{}{}".format(client_salt, user_salt))

        # since sub can be public, there can be more then one session
        # that uses the same subject identifier

        self.sso_db.map_sid2uid(sid, uid)
        self.update(sid, sub=sub)
        self.sso_db.map_sid2sub(sid, sub)

        return sub

    def create_authz_session(self, aevent, areq, id_token=None, oidreq=None,
                             **kwargs):
        """

        :param aevent: An AuthnEvent instance
        :param areq: The AuthorizationRequest instance
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :return: The session identifier, which is the database key
        """

        sid = self.handler['code'].key(user=aevent.uid, areq=areq)
        access_grant = self.handler['code'](sid=sid)

        _dic = {
            "oauth_state": "authz",
            "code": access_grant,
            "authzreq": areq.to_json(),
            "client_id": areq["client_id"],
            'response_type': areq['response_type'],
            "authn_event": aevent
        }

        _dic.update(kwargs)

        try:
            _val = areq["nonce"]
            if _val:
                _dic["nonce"] = _val
        except (AttributeError, KeyError):
            pass

        for key in ["redirect_uri", "state", "scope", "si_redirects"]:
            try:
                _dic[key] = areq[key]
            except KeyError:
                pass

        if id_token:
            _dic["id_token"] = id_token
        if oidreq:
            _dic["oidreq"] = oidreq.to_json()

        # Add to SSO db
        self.sso_db.map_sid2uid(sid, aevent.uid)
        self._db[sid] = _dic

        return sid

    def get_authentication_event(self, sid):
        return self._db[sid]["authn_event"]

    def get_token(self, sid):
        if self._db[sid]["oauth_state"] == "authz":
            return self._db[sid]["code"]
        elif self._db[sid]["oauth_state"] == "token":
            return self._db[sid]["access_token"]

    def replace_token(self, sid, sinfo, token_type):
        """
        Replace an old refresh_token with a new one

        :param sid: session ID
        :param sinfo: session info
        :param token_type: What type of tokens should be replaced
        :return: Updated session info
        """
        try:
            # Mint a new one
            refresh_token = self.handler[token_type](sid, sinfo=sinfo)
        except KeyError:
            pass
        else:
            # blacklist the old is there is one
            try:
                self.handler[token_type].black_list(sinfo[token_type])
            except KeyError:
                pass

            sinfo[token_type] = refresh_token

        return sinfo

    def upgrade_to_token(self, grant=None, issue_refresh=False, id_token="",
                         oidreq=None, key=None, scope=None):
        """

        :param grant: The access grant
        :param issue_refresh: If a refresh token should be issued
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :param key: The session key. One of grant or key must be given.
        :return: The session information as a dictionary
        """
        if grant:
            _tinfo = self.handler['code'].info(grant)

            dic = self._db[_tinfo['sid']]

            if self.handler['code'].is_black_listed(grant):
                # invalidate the released access token and refresh token
                for item in ['access_token', 'refresh_token']:
                    try:
                        self.handler[item].black_list(dic[item])
                    except KeyError:
                        pass
                raise AccessCodeUsed(grant)

            # mint a new access token
            _at = self.handler['access_token'](sid=_tinfo['sid'], sinfo=dic)

            # make sure the code can't be used again
            self.handler['code'].black_list(grant)
            key = _tinfo['sid']
        else:
            dic = self._db[key]
            _at = self.handler['access_token'](sid=key, sinfo=dic)

        dic["access_token"] = _at
        dic["oauth_state"] = "token"
        dic["token_type"] = self.handler['access_token'].token_type

        if scope:
            dic["access_token_scope"] = scope
        if id_token:
            dic["id_token"] = id_token
        if oidreq:
            dic["oidreq"] = oidreq

        if issue_refresh:
            dic = self.replace_token(key, dic, 'refresh_token')

        self._db[key] = dic
        return dic

    def refresh_token(self, token, new_refresh=False):
        """
        Issue a new access token using a valid refresh token

        :param token: Refresh token
        :param new_refresh: Whether a new refresh token should be minted or not
        :return: Dictionary with session info
        :raises: ExpiredToken for invalid refresh token
                 WrongTokenType for wrong token type
        """

        try:
            _tinfo = self.handler['refresh_token'].info(token)
        except KeyError:
            return False

        if is_expired(int(_tinfo['exp'])) or _tinfo['black_listed']:
            raise ExpiredToken()

        _sid = _tinfo['sid']
        dic = self._db[_sid]

        dic = self.replace_token(_sid, dic, 'access_token')

        dic["token_type"] = self.handler['access_token'].token_type

        if new_refresh:
            dic = self.replace_token(_sid, dic, 'refresh_token')

        self._db[_sid] = dic
        return dic

    def is_token_valid(self, token):
        """
        Checks validity of a given token

        :param token: Access or refresh token
        """

        try:
            _tinfo = self.handler.info(token)
        except KeyError:
            return False

        if is_expired(int(_tinfo['exp'])) or _tinfo['black_listed']:
            return False

        # Dependent on what state the session is in.
        _dic = self._db[_tinfo['sid']]

        if _dic["oauth_state"] == "authz":
            if _tinfo['handler'] != self.handler['code']:
                return False
        elif _dic["oauth_state"] == "token":
            if _tinfo['handler'] != self.handler['access_token']:
                return False

        return True

    def revoke_token(self, token, token_type=''):
        """
        Revokes access token

        :param token: access token
        """
        if token_type:
            self.handler[token_type].black_list(token)
        else:
            self.handler.black_list(token)

    def revoke_all_tokens(self, token):
        _sinfo = self[token]
        for typ in self.handler.keys():
            try:
                self.revoke_token(_sinfo[typ], typ)
            except KeyError:
                pass

    def revoke_session(self, token):
        """
        Mark session as revoked but also explicitly revoke all issued tokens

        :param token: any token connectd to the session
        """
        sid = self.handler.sid(token)

        for typ in ['access_token', 'refresh_token', 'code']:
            self.revoke_token(self._db[sid][typ], typ)

        self.update(sid, revoked=True)

    def get_client_id_for_session(self, sid):
        return self._db[sid]["client_id"]

    def get_active_client_ids_for_uid(self, uid):
        res = []
        for sid in self.sso_db.get_sids_by_uid(uid):
            if 'revoked' not in self._db[sid]:
                res.append(self._db[sid]["client_id"])
        return res

    def get_verified_logout(self, uid):
        res = {}
        for sid in self.sso_db.get_sids_by_uid(uid):
            _dict = self._db[sid]
            try:
                res[_dict['client_id']] = _dict['verified_logout']
            except KeyError:
                res[_dict['client_id']] = False
        return res

    def match_session(self, uid, **kwargs):
        for sid in self.sso_db.get_sids_by_uid(uid):
            _dict = self._db[sid]
            if dict_match(kwargs, _dict):
                return sid
        return None

    def set_verify_logout(self, uid, client_id):
        sid = self.match_session(uid, client_id=client_id)
        self._db[sid]['verified_logout'] = True

    def get_id_token(self, uid, client_id):
        sid = self.match_session(uid, client_id=client_id)
        return self._db[sid]['id_token']

    def is_session_revoked(self, key):
        try:
            _tinfo = self[key]
        except Exception:
            raise UnknownToken(key)

        try:
            return _tinfo['revoked']
        except KeyError:
            return False

    def revoke_uid(self, uid):
        # Revoke all sessions
        for sid in self.sso_db.get_sids_by_uid(uid):
            self._db['revoked'] = True
        # Remove the uid from the SSO db
        self.sso_db.remove_uid(uid)

    def duplicate(self, sinfo):
        _dic = copy.copy(sinfo)
        areq = AuthorizationRequest().from_json(_dic["authzreq"])
        sid = self.handler['code'].key(user=_dic["sub"], areq=areq)

        _dic["code"] = self.handler['code'](sid=sid, sinfo=sinfo)

        for key in ["access_token", "access_token_scope", "oauth_state",
                    "token_type", "token_expires_at", "expires_in",
                    "client_id_issued_at", "id_token", "oidreq",
                    "refresh_token"]:
            try:
                del _dic[key]
            except KeyError:
                pass

        self._db[sid] = _dic
        self.sso_db.map_sid2sub(sid, _dic["sub"])
        return sid

    def read(self, token):
        try:
            _tinfo = self.handler['access_token'].info(token)
        except WrongTokenType:
            return {}
        else:
            return self._db[_tinfo['sid']]

    def find_sid(self, req):
        """
        Given a request with some info find the correct session
        The useful claims are 'redirect_uri' and 'code'.
        
        :param req: An AccessTokenRequest instance 
        :return: session ID
        """
        _code = req['code']
        _ruri = req['redirect_uri']

        for k, v in self._db.item():
            if v['code'] == _code and v['redirect_uri'] == _ruri:
                return k
        return None
