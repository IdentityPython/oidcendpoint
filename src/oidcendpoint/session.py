import hashlib
import json
import time

from oidcmsg.exception import MissingParameter
from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import msg_ser
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.time_util import utc_time_sans_frac

from oidcendpoint import token_handler
from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.in_memory_db import InMemoryDataBase
from oidcendpoint.sso_db import KEY_FORMAT
from oidcendpoint.sso_db import SSODb
from oidcendpoint.token_handler import ExpiredToken
from oidcendpoint.token_handler import UnknownToken
from oidcendpoint.token_handler import WrongTokenType
from oidcendpoint.token_handler import is_expired


def authorization_request_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return AuthorizationRequest().deserialize(val, sformat)


SINGLE_REQUIRED_AUTHORIZATION_REQUEST = (
    Message,
    True,
    msg_ser,
    authorization_request_deser,
    False,
)


def authn_event_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, str):
            val = json.dumps(val)
            sformat = "json"
    return AuthnEvent().deserialize(val, sformat)


def setup_session(
        endpoint_context, areq, uid, client_id="", acr="", salt="salt", authn_event=None
):
    """
    Setting up a user session

    :param endpoint_context:
    :param areq:
    :param uid:
    :param acr:
    :param client_id:
    :param salt:
    :param authn_event: A already made AuthnEvent
    :return:
    """
    if authn_event is None and acr:
        authn_event = AuthnEvent(
            uid=uid, salt=salt, authn_info=acr, authn_time=time.time()
        )

    if not client_id:
        client_id = areq["client_id"]

    sid = endpoint_context.sdb.create_authz_session(
        authn_event, areq, client_id=client_id, uid=uid
    )

    client_salt = endpoint_context.cdb.get(client_id, {}).get("client_salt", salt)
    endpoint_context.sdb.do_sub(sid, uid, client_salt)
    return sid


SINGLE_REQUIRED_AUTHN_EVENT = (Message, True, msg_ser, authn_event_deser, False)


class SessionInfo(Message):
    c_param = {
        "oauth_state": SINGLE_REQUIRED_STRING,
        "code": SINGLE_OPTIONAL_STRING,
        "authn_req": SINGLE_REQUIRED_AUTHORIZATION_REQUEST,
        "client_id": SINGLE_REQUIRED_STRING,
        "authn_event": SINGLE_REQUIRED_AUTHN_EVENT,
        "si_redirects": OPTIONAL_LIST_OF_STRINGS,
    }


def pairwise_id(uid, sector_identifier, salt, **kwargs):
    return hashlib.sha256(
        ("%s%s%s" % (uid, sector_identifier, salt)).encode("utf-8")
    ).hexdigest()


def public_id(uid, salt="", **kwargs):
    return hashlib.sha256("{}{}".format(uid, salt).encode("utf-8")).hexdigest()


def dict_match(a, b):
    """
    Check if all attribute/value pairs in a also appears in b

    :param a: A dictionary
    :param b: A dictionary
    :return: True/False
    """
    res = []
    for k, v in a.items():
        try:
            res.append(b[k] == v)
        except KeyError:
            pass
    return all(res)


class SessionDB(object):
    def __init__(self, db, handler, sso_db=SSODb(), userinfo=None, sub_func=None):
        # db must implement the InMemoryDataBase interface
        self._db = db
        self.handler = handler
        self.sso_db = sso_db
        self.userinfo = userinfo

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

    def __getitem__(self, item):
        _info = self._db.get(item)

        if _info is None:
            sid = self.handler.sid(item)
            _info = self._db.get(sid)
            if _info:
                _si = SessionInfo().from_json(_info)
                if any(item == val for val in _si.values()):
                    _si['sid'] = sid
                    return _si
        else:
            _si = SessionInfo().from_json(_info)
            _si['sid'] = item
            return _si
        raise KeyError

    def __setitem__(self, sid, instance):
        try:
            _info = instance.to_json()
        except ValueError:
            _info = json.dumps(instance)
        self._db.set(sid, _info)

    def __delitem__(self, key):
        self._db.delete(key)

    def keys(self):
        return self._db.keys()

    def create_authz_session(self, authn_event, areq, client_id="", uid="", **kwargs):
        """

        :param authn_event:
        :param areq:
        :param client_id:
        :param uid:
        :param kwargs:
        :return:
        """
        try:
            _uid = authn_event["uid"]
        except (TypeError, KeyError):
            _uid = uid

        if not _uid:
            raise MissingParameter('Need a "uid"')

        sid = self.handler["code"].key(user=_uid, areq=areq)

        access_grant = self.handler["code"](sid=sid)

        _info = SessionInfo(code=access_grant, oauth_state="authz")

        if client_id:
            _info["client_id"] = client_id

        if areq:
            _info["authn_req"] = areq
            self.map_kv2sid("state", areq["state"], sid)
        if authn_event:
            _info["authn_event"] = authn_event

        if kwargs:
            _info.update(kwargs)

        self[sid] = _info
        return sid

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

    def map_kv2sid(self, key, value, sid):
        """ KEY_FORMAT = "__{}__{}" """
        self._db.set(KEY_FORMAT.format(key, value), sid)

    def delete_kv2sid(self, key, value):
        self._db.delete(KEY_FORMAT.format(key, value))

    def get_sid_by_kv(self, key, value):
        """ KEY_FORMAT = "__{}__{}" """
        return self._db.get(KEY_FORMAT.format(key, value))

    def get_token(self, sid):
        _sess_info = self[sid]

        if _sess_info["oauth_state"] == "authz":
            return _sess_info["code"]
        elif _sess_info["oauth_state"] == "token":
            return _sess_info["access_token"]

    def do_sub(
            self, sid, uid, client_salt, sector_id="", subject_type="public", user_salt=""
    ):
        """
        Create and store a subject identifier

        :param sid: Session ID
        :param uid: User ID
        :param client_salt:
        :param sector_id: For pairwise identifiers, an Identifier for the RP group
        :param subject_type: 'pairwaise'/'public'
        :param user_salt:
        :return:
        """
        sub = self.sub_func[subject_type](
            uid, salt=client_salt or user_salt, sector_identifier=sector_id
        )

        self.sso_db.map_sid2uid(sid, uid)
        self.update(sid, sub=sub)
        self.sso_db.map_sid2sub(sid, sub)

        return sub

    def is_valid(self, typ, item):
        try:
            return typ in self[item]
        except KeyError:
            return False

    def get_sids_by_sub(self, sub):
        return self.sso_db.get_sids_by_sub(sub)

    def get_sid_by_sub_and_client_id(self, sub, client_id):
        for sid in self.sso_db.get_sids_by_sub(sub):
            if self[sid]["authn_req"]["client_id"] == client_id:
                return sid
        return None

    def replace_refresh_token(self, sid, sinfo):
        """
        Replace an old refresh_token with a new one

        :param sid: session ID
        :param sinfo: session info
        :return: Updated session info
        """
        refresh_token = self.handler["refresh_token"](sid, sinfo=sinfo)
        sinfo["refresh_token"] = refresh_token
        return sinfo

    def _make_at(self, sid, session_info, aud=None, client_id_aud=True):
        uid = self.sso_db.get_uid_by_sid(sid)

        uinfo = self.userinfo(uid, session_info["client_id"]) or {}
        at_aud = aud or []

        if client_id_aud:
            at_aud.append(session_info["client_id"])
        return self.handler["access_token"](
            sid=sid, sinfo=session_info, uinfo=uinfo, aud=at_aud
        )

    def upgrade_to_token(
            self,
            grant=None,
            issue_refresh=False,
            id_token="",
            oidreq=None,
            key=None,
            scope=None,
    ):
        """

        :param grant: The access grant
        :param issue_refresh: If a refresh token should be issued
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :param key: The session key. One of grant or key must be given.
        :return: The session information as a SessionInfo instance
        """
        if grant:
            # The caller is responsible for checking if the access code exists.
            _tinfo = self.handler["code"].info(grant)

            key = _tinfo["sid"]
            session_info = self[key]

            # mint a new access token
            _at = self._make_at(_tinfo["sid"], session_info)

            # make sure the code can't be used again
            self.revoke_token(key, "code", session_info)
        else:
            session_info = self[key]
            _at = self._make_at(key, session_info)

        session_info["access_token"] = _at
        session_info["oauth_state"] = "token"
        session_info["token_type"] = self.handler["access_token"].token_type

        if scope:
            session_info["access_token_scope"] = scope
        if id_token:
            session_info["id_token"] = id_token
        if oidreq:
            session_info["oidreq"] = oidreq

        if self.handler["access_token"].lifetime:
            session_info["expires_in"] = self.handler["access_token"].lifetime
            session_info["expires_at"] = self.handler[
                                             "access_token"].lifetime + utc_time_sans_frac()

        if issue_refresh and "refresh_token" in self.handler:
            session_info = self.replace_refresh_token(key, session_info)

        self[key] = session_info
        return session_info

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
            _tinfo = self.handler["refresh_token"].info(token)
        except KeyError:
            return False

        _sid = _tinfo["sid"]
        session_info = self[_sid]
        if token != session_info.get("refresh_token"):
            raise UnknownToken()
        if is_expired(int(_tinfo["exp"])):
            raise ExpiredToken()

        session_info["access_token"] = self._make_at(_sid, session_info)
        session_info["token_type"] = self.handler["access_token"].token_type

        if new_refresh:
            session_info = self.replace_refresh_token(_sid, session_info)

        self[_sid] = session_info
        return session_info

    def is_token_valid(self, token):
        """
        Checks validity of a given token

        :param token: Access or refresh token
        """

        try:
            _tinfo = self.handler.info(token)
        except KeyError:
            return False

        # Dependent on what state the session is in.
        session_info = self[_tinfo["sid"]]
        if is_expired(int(_tinfo["exp"])):
            return False

        if session_info["oauth_state"] == "authz":
            if _tinfo["handler"] != self.handler["code"]:
                return False
        elif session_info["oauth_state"] == "token":
            if _tinfo["handler"] != self.handler["access_token"]:
                return False

        return True

    def revoke_token(self, sid, token_type, session_info=None):
        """
        Revokes token

        :param sid: session id
        :param token_type: token type, one of "code", "access_token" or
            "refresh_token"
        """
        if not session_info:
            session_info = self[sid]
        session_info.pop(token_type, None)
        self[sid] = session_info

    def revoke_all_tokens(self, token):
        sid = self.handler.sid(token)
        _sinfo = self[sid]
        for token_type in self.handler.keys():
            _sinfo.pop(token_type, None)
        self[sid] = _sinfo

    def revoke_session(self, sid="", token=""):
        """
        Mark session as revoked but also explicitly revoke all issued tokens

        :param token: any token connected to the session
        :param sid: Session identifier
        """
        if not sid:
            if token:
                sid = self.handler.sid(token)
            else:
                raise ValueError('Need one of "sid" or "token"')

        _sinfo = self[sid]
        for token_type in self.handler.keys():
            _sinfo.pop(token_type, None)

        self.update(sid, revoked=True)

    def get_client_id_for_session(self, sid):
        return self[sid]["client_id"]

    def get_active_client_ids_for_uid(self, uid):
        res = []
        for sid in self.sso_db.get_sids_by_uid(uid):
            if "revoked" not in self[sid]:
                res.append(self[sid]["client_id"])
        return res

    def get_verified_logout(self, uid):
        res = {}
        for sid in self.sso_db.get_sids_by_uid(uid):
            session_info = self[sid]
            try:
                res[session_info["client_id"]] = session_info["verified_logout"]
            except KeyError:
                res[session_info["client_id"]] = False
        return res

    def match_session(self, uid, **kwargs):
        for sid in self.sso_db.get_sids_by_uid(uid):
            session_info = self[sid]
            if dict_match(kwargs, session_info):
                return sid
        return None

    def set_verify_logout(self, uid, client_id):
        sid = self.match_session(uid, client_id=client_id)
        self.update(sid, verified_logout=True)

    def get_id_token(self, uid, client_id):
        sid = self.match_session(uid, client_id=client_id)
        return self[sid]["id_token"]

    def is_session_revoked(self, key):
        try:
            session_info = self[key]
        except Exception:
            raise UnknownToken(key)

        try:
            return session_info["revoked"]
        except KeyError:
            return False

    def revoke_uid(self, uid):
        # Revoke all sessions
        for sid in self.sso_db.get_sids_by_uid(uid):
            self.update(sid, revoked=True)

        # Remove the uid from the SSO db
        self.sso_db.remove_uid(uid)

    def read(self, token):
        try:
            _tinfo = self.handler["access_token"].info(token)
        except WrongTokenType:
            return {}
        else:
            return self[_tinfo["sid"]]

    def find_sid(self, req):
        """
        Given a request with some info find the correct session.
        The useful claim is 'code'.

        :param req: An AccessTokenRequest instance
        :return: session ID or None
        """

        return self.get_sid_by_kv("code", req["code"])

    def get_authentication_event(self, sid):
        try:
            session_info = self[sid]
        except Exception:
            raise UnknownToken(sid)
        else:
            sesinf = session_info.get("authn_event")
            return sesinf or ValueError("No Authn event info")


def create_session_db(ec, token_handler_args, db=None, sso_db=None, sub_func=None):
    _token_handler = token_handler.factory(ec, **token_handler_args)
    db = db or InMemoryDataBase()
    sso_db = sso_db or SSODb()
    return SessionDB(db, _token_handler, sso_db, sub_func=sub_func)
