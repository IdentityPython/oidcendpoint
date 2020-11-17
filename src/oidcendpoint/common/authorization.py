import logging
from urllib.parse import unquote
from urllib.parse import urlencode
from urllib.parse import urlparse

from oidcmsg.time_util import time_sans_frac

from oidcendpoint.session_management import unpack_session_key
from oidcmsg.exception import ParameterError
from oidcmsg.exception import URIError
from oidcmsg.message import Message
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import verified_claim_name

from oidcendpoint import sanitize
from oidcendpoint.exception import RedirectURIError
from oidcendpoint.exception import UnknownClient
from oidcendpoint.util import split_uri

logger = logging.getLogger(__name__)

FORM_POST = """<html>
  <head>
    <title>Submit This Form</title>
  </head>
  <body onload="javascript:document.forms[0].submit()">
    <form method="post" action="{action}">
        {inputs}
    </form>
  </body>
</html>"""


def inputs(form_args):
    """
    Creates list of input elements
    """
    element = []
    html_field = '<input type="hidden" name="{}" value="{}"/>'
    for name, value in form_args.items():
        element.append(html_field.format(name, value))
    return "\n".join(element)


def max_age(request):
    verified_request = verified_claim_name("request")
    return request.get(verified_request, {}).get("max_age") or request.get("max_age", 0)


def verify_uri(endpoint_context, request, uri_type, client_id=None):
    """
    A redirect URI
    MUST NOT contain a fragment
    MAY contain query component

    :param endpoint_context: An EndpointContext instance
    :param request: The authorization request
    :param uri_type: redirect_uri or post_logout_redirect_uri
    :return: An error response if the redirect URI is faulty otherwise
        None
    """
    _cid = request.get("client_id", client_id)

    if not _cid:
        logger.error("No client id found")
        raise UnknownClient("No client_id provided")
    else:
        logger.debug("Client ID: {}".format(_cid))

    _redirect_uri = unquote(request[uri_type])

    part = urlparse(_redirect_uri)
    if part.fragment:
        raise URIError("Contains fragment")

    (_base, _query) = split_uri(_redirect_uri)
    # if _query:
    #     _query = parse_qs(_query)

    match = False
    # Get the clients registered redirect uris
    client_info = endpoint_context.cdb.get(_cid, {})
    if not client_info:
        raise KeyError("No such client")
    logger.debug("Client info: {}".format(client_info))
    redirect_uris = client_info.get("{}s".format(uri_type))
    if not redirect_uris:
        if _cid not in endpoint_context.cdb:
            logger.debug("CIDs: {}".format(list(endpoint_context.cdb.keys())))
            raise KeyError("No such client")
        raise ValueError("No registered {}".format(uri_type))
    else:
        for regbase, rquery in redirect_uris:
            # The URI MUST exactly match one of the Redirection URI
            if _base == regbase:
                # every registered query component must exist in the uri
                if rquery:
                    if not _query:
                        raise ValueError("Missing query part")

                    for key, vals in rquery.items():
                        if key not in _query:
                            raise ValueError('"{}" not in query part'.format(key))

                        for val in vals:
                            if val not in _query[key]:
                                raise ValueError(
                                    "{}={} value not in query part".format(key, val)
                                )

                # and vice versa, every query component in the uri
                # must be registered
                if _query:
                    if not rquery:
                        raise ValueError("No registered query part")

                    for key, vals in _query.items():
                        if key not in rquery:
                            raise ValueError('"{}" extra in query part'.format(key))
                        for val in vals:
                            if val not in rquery[key]:
                                raise ValueError(
                                    "Extra {}={} value in query part".format(key, val)
                                )
                match = True
                break
        if not match:
            raise RedirectURIError("Doesn't match any registered uris")


def join_query(base, query):
    """

    :param base: URL base
    :param query: query part as a dictionary
    :return:
    """
    if query:
        return "{}?{}".format(base, urlencode(query, doseq=True))
    else:
        return base


def get_uri(endpoint_context, request, uri_type):
    """ verify that the redirect URI is reasonable.

    :param endpoint_context: An EndpointContext instance
    :param request: The Authorization request
    :param uri_type: 'redirect_uri' or 'post_logout_redirect_uri'
    :return: redirect_uri
    """
    uri = ""

    if uri_type in request:
        verify_uri(endpoint_context, request, uri_type)
        uri = request[uri_type]
    else:
        uris = "{}s".format(uri_type)
        client_id = str(request["client_id"])
        if client_id in endpoint_context.cdb:
            _specs = endpoint_context.cdb[client_id].get(uris)
            if not _specs:
                raise ParameterError("Missing {} and none registered".format(uri_type))

            if len(_specs) > 1:
                raise ParameterError(
                    "Missing {} and more than one registered".format(uri_type)
                )

            uri = join_query(*_specs[0])

    return uri


def authn_args_gather(request, authn_class_ref, cinfo, **kwargs):
    """
    Gather information to be used by the authentication method

    :param request: The request either as a dictionary or as a Message instance
    :param authn_class_ref: Authentication class reference
    :param cinfo: Client information
    :param kwargs: Extra keyword arguments
    :return: Authentication arguments
    """
    authn_args = {
        "authn_class_ref": authn_class_ref,
        "return_uri": request["redirect_uri"],
    }

    if isinstance(request, Message):
        authn_args["query"] = request.to_urlencoded()
    elif isinstance(request, dict):
        authn_args["query"] = urlencode(request)
    else:
        ValueError("Wrong request format")

    if "req_user" in kwargs:
        authn_args["as_user"] = (kwargs["req_user"],)

    # Below are OIDC specific. Just ignore if OAuth2
    if cinfo:
        for attr in ["policy_uri", "logo_uri", "tos_uri"]:
            if cinfo.get(attr):
                authn_args[attr] = cinfo[attr]

    for attr in ["ui_locales", "acr_values", "login_hint"]:
        if request.get(attr):
            authn_args[attr] = request[attr]

    return authn_args


def create_authn_response(endpoint, request, sid):
    """

    :param endpoint:
    :param request:
    :param sid:
    :return:
    """
    # create the response
    aresp = AuthorizationResponse()
    if request.get("state"):
        aresp["state"] = request["state"]

    if "response_type" in request and request["response_type"] == ["none"]:
        fragment_enc = False
    else:
        _context = endpoint.endpoint_context
        _mngr = endpoint.endpoint_context.session_manager
        _session_info = _mngr[sid]

        if request.get("scope"):
            aresp["scope"] = request["scope"]

        rtype = set(request["response_type"][:])
        handled_response_type = []

        fragment_enc = True

        if len(rtype) == 1 and "code" in rtype:
            fragment_enc = False

            grant = _mngr.grants(sid)[0]
            user_id, client_id = unpack_session_key(sid)

            if "code" in request["response_type"]:
                _code = grant.mint_token(
                    'authorization_code',
                    value=_mngr.token_handler["code"](user_id),
                    expires_at=time_sans_frac() + 300  # 5 minutes from now
                )
                aresp["code"] = _code.value
                handled_response_type.append("code")
            else:
                _code = None

            if "token" in rtype:
                _access_token = grant.mint_token(
                    "access_token",
                    value=_mngr.token_handler["access_token"](
                        sid,
                        client_id=client_id,
                        aud=grant.resources,
                        user_claims=None,
                        scope=grant.scope,
                        sub=_session_info['sub'],
                        based_on=_code
                    ),
                    expires_at=time_sans_frac() + 900
                )

                aresp['token'] = _access_token
                handled_response_type.append("token")

        not_handled = rtype.difference(handled_response_type)
        if not_handled:
            resp = AuthorizationErrorResponse(
                error="invalid_request", error_description="unsupported_response_type"
            )
            return {"response_args": resp, "fragment_enc": fragment_enc}

    return {"response_args": aresp, "fragment_enc": fragment_enc}


class AllowedAlgorithms:
    def __init__(self, algorithm_parameters):
        self.algorithm_parameters = algorithm_parameters

    def __call__(self, client_id, endpoint_context, alg, alg_type):
        _cinfo = endpoint_context.cdb[client_id]
        _pinfo = endpoint_context.provider_info

        _reg, _sup = self.algorithm_parameters[alg_type]
        _allowed = _cinfo.get(_reg)
        if _allowed is None:
            _allowed = _pinfo.get(_sup)

        if alg not in _allowed:
            logger.error(
                "Signing alg user: {} not among allowed: {}".format(alg, _allowed)
            )
            raise ValueError("Not allowed '%s' algorithm used", alg)


def re_authenticate(request, authn):
    return False
