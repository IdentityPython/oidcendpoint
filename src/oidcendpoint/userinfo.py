import logging

from oidcservice import sanitize
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import Claims
from oidcmsg.oidc import scope2claims
from oidcmsg.oidc import OpenIDRequest

from oidcendpoint.exception import FailedAuthentication

logger = logging.getLogger(__name__)


def id_token_claims(session):
    """
    Pick the IdToken claims from the request

    :param session: Session information
    :return: The IdToken claims
    """
    itc = {}
    itc = update_claims(session, "authzreq", "id_token", itc)
    itc = update_claims(session, "oidreq", "id_token", itc)
    return itc


def update_claims(session, where, about, old_claims=None):
    """

    :param session:
    :param where: Which request
    :param about: userinfo or id_token
    :param old_claims:
    :return: claims or None
    """

    if old_claims is None:
        old_claims = {}

    req = None
    if where == "oidreq":
        try:
            req = OpenIDRequest().deserialize(session[where], "json")
        except KeyError:
            pass
    elif where == "authzreq":
        try:
            req = AuthorizationRequest().deserialize(session[where], "json")
        except KeyError:
            pass
    else:
        raise ValueError('Unknown request specifier: {}'.format(where))

    if req:
        logger.debug("%s: %s" % (where, sanitize(req.to_dict())))
        try:
            _claims = req["claims"][about]
        except KeyError:
            pass
        else:
            if _claims:
                # update with old claims, do not overwrite
                for key, val in old_claims.items():
                    if key not in _claims:
                        _claims[key] = val
                return _claims

    return old_claims


def claims_match(value, claimspec):
    """
    Implements matching according to section 5.5.1 of
    http://openid.net/specs/openid-connect-core-1_0.html
    The lack of value is not checked here.
    Also the text doesn't prohibit having both 'value' and 'values'.

    :param value: single value
    :param claimspec: None or dictionary with 'essential', 'value' or 'values'
        as key
    :return: Boolean
    """
    if claimspec is None:  # match anything
        return True

    matched = False
    for key, val in claimspec.items():
        if key == "value":
            if value == val:
                matched = True
        elif key == "values":
            if value in val:
                matched = True
        elif key == 'essential':
            # Whether it's essential or not doesn't change anything here
            continue

        if matched:
            break

    if matched is False:
        if list(claimspec.keys()) == ['essential']:
            return True

    return matched


def by_schema(cls, **kwa):
    """
    Will return only those claims that are listed in the Class definition.

    :param cls: A subclass of :py:class:´oidcmsg.message.Message`
    :param kwa: Keyword arguments
    :return: A dictionary with claims (keys) that meets the filter criteria
    """
    return dict([(key, val) for key, val in kwa.items() if key in cls.c_param])


def collect_user_info(endpoint_context, session, userinfo_claims=None):
    """
    Collect information about a user.
    This can happen in two cases, either when constructing an IdToken or
    when returning user info through the UserInfo endpoint

    :param session: Session information
    :param userinfo_claims: user info claims
    :return: User info
    """
    if userinfo_claims is None:
        uic = scope2claims(session["scope"])

        # Get only keys allowed by user and update the dict if such info
        # is stored in session
        perm_set = session.get('permission')
        if perm_set:
            uic = {key: uic[key] for key in uic if key in perm_set}

        if "oidreq" in session:
            uic = update_claims(session, "oidreq", "userinfo",
                                uic)
        else:
            uic = update_claims(session, "authzreq", "userinfo",
                                uic)
        if uic:
            userinfo_claims = Claims(**uic)
        else:
            userinfo_claims = None

        logger.debug(
            "userinfo_claim: %s" % sanitize(userinfo_claims.to_dict()))

    logger.debug("Session info: %s" % sanitize(session))

    authn_event = session.get("authn_event")
    if authn_event:
        uid = authn_event["uid"]
    else:
        uid = session['uid']

    info = endpoint_context.userinfo(uid, session['client_id'], userinfo_claims)

    if "sub" in userinfo_claims:
        if not claims_match(session["sub"], userinfo_claims["sub"]):
            raise FailedAuthentication("Unmatched sub claim")

    info["sub"] = session["sub"]
    try:
        logger.debug("user_info_response: {}".format(info))
    except UnicodeEncodeError:
        try:
            logger.debug(
                "user_info_response: {}".format(info.encode('utf-8')))
        except Exception:
            pass

    return info


def userinfo_in_id_token_claims(endpoint_context, session):
    """
    Put userinfo claims in the id token
    :param session:
    :return:
    """
    itc = id_token_claims(session)
    if not itc:
        return None

    _claims = by_schema(endpoint_context.id_token_schema, **itc)

    if _claims:
        return collect_user_info(session, _claims)
    else:
        return None

