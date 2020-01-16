import logging

from oidcmsg.oidc import Claims

from oidcendpoint import sanitize
from oidcendpoint.exception import FailedAuthentication
from oidcendpoint.user_info import scope2claims

logger = logging.getLogger(__name__)


def id_token_claims(session, provider_info):
    """
    Pick the IdToken claims from the request

    :param session: Session information
    :return: The IdToken claims
    """
    itc = update_claims(session, "id_token", provider_info=provider_info, old_claims={})
    return itc


def update_claims(session, about, provider_info, old_claims=None):
    """

    :param session:
    :param about: userinfo or id_token
    :param old_claims:
    :return: claims or None
    """

    if old_claims is None:
        old_claims = {}

    req = None
    try:
        req = session["authn_req"]
    except KeyError:
        pass

    if req:
        try:
            _claims = req["claims"][about]
        except KeyError:
            pass
        else:
            if _claims:
                # Deal only with supported claims
                _unsup = [c for c in _claims.keys() if c not in provider_info["claims_supported"]]
                for _c in _unsup:
                    del _claims[_c]

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
        elif key == "essential":
            # Whether it's essential or not doesn't change anything here
            continue

        if matched:
            break

    if matched is False:
        if list(claimspec.keys()) == ["essential"]:
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


def collect_user_info(
        endpoint_context, session, userinfo_claims=None, scope_to_claims=None
):
    """
    Collect information about a user.
    This can happen in two cases, either when constructing an IdToken or
    when returning user info through the UserInfo endpoint

    :param session: Session information
    :param userinfo_claims: user info claims
    :return: User info
    """
    authn_req = session["authn_req"]
    if scope_to_claims is None:
        scope_to_claims = endpoint_context.scope2claims

    supported_scopes = [s for s in authn_req["scope"] if
                        s in endpoint_context.provider_info["scopes_supported"]]

    if userinfo_claims is None:
        uic = scope2claims(supported_scopes, map=scope_to_claims)

        # Get only keys allowed by user and update the dict if such info
        # is stored in session
        perm_set = session.get("permission")
        if perm_set:
            uic = {key: uic[key] for key in uic if key in perm_set}

        uic = update_claims(session, "userinfo",
                            provider_info=endpoint_context.provider_info,
                            old_claims=uic)

        if uic:
            userinfo_claims = Claims(**uic)
        else:
            userinfo_claims = None

        logger.debug("userinfo_claim: %s" % sanitize(userinfo_claims.to_dict()))

    logger.debug("Session info: %s" % sanitize(session))

    authn_event = session["authn_event"]
    if authn_event:
        uid = authn_event["uid"]
    else:
        uid = session["uid"]

    info = endpoint_context.userinfo(uid, authn_req["client_id"], userinfo_claims)

    if "sub" in userinfo_claims:
        if not claims_match(session["sub"], userinfo_claims["sub"]):
            raise FailedAuthentication("Unmatched sub claim")

    info["sub"] = session["sub"]
    try:
        logger.debug("user_info_response: {}".format(info))
    except UnicodeEncodeError:
        logger.debug("user_info_response: {}".format(info.encode("utf-8")))

    return info


def userinfo_in_id_token_claims(endpoint_context, session, def_itc=None):
    """
    Collect user info claims that are to be placed in the id token.

    :param endpoint_context: Endpoint context
    :param session: Session information
    :param def_itc: Default ID Token claims
    :return: User information or None
    """
    if def_itc:
        itc = def_itc
    else:
        itc = {}

    itc.update(id_token_claims(session, provider_info=endpoint_context.provider_info))

    if not itc:
        return None

    _claims = by_schema(endpoint_context.id_token_schema, **itc)

    if _claims:
        return collect_user_info(endpoint_context, session, _claims)
    else:
        return None
