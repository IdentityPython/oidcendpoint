import logging
from urllib.parse import parse_qs
from urllib.parse import splitquery
from urllib.parse import unquote
from urllib.parse import urlencode
from urllib.parse import urlparse

from oidcmsg.exception import ParameterError
from oidcmsg.exception import URIError
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import verified_claim_name

from oidcendpoint import sanitize
from oidcendpoint.exception import RedirectURIError
from oidcendpoint.exception import UnknownClient
from oidcendpoint.user_info import SCOPE2CLAIMS

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

DEFAULT_SCOPES = list(SCOPE2CLAIMS.keys())
_CLAIMS = set()
for scope, claims in SCOPE2CLAIMS.items():
    _CLAIMS.update(set(claims))
DEFAULT_CLAIMS = list(_CLAIMS)


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

    _redirect_uri = unquote(request[uri_type])

    part = urlparse(_redirect_uri)
    if part.fragment:
        raise URIError("Contains fragment")

    (_base, _query) = splitquery(_redirect_uri)
    if _query:
        _query = parse_qs(_query)

    match = False
    # Get the clients registered redirect uris
    redirect_uris = endpoint_context.cdb.get(_cid, {}).get("{}s".format(uri_type))
    if not redirect_uris:
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
    """
    authn_args = {
        "authn_class_ref": authn_class_ref,
        "query": request.to_urlencoded(),
        "return_uri": request["redirect_uri"],
    }

    if "req_user" in kwargs:
        authn_args["as_user"] = (kwargs["req_user"],)

    # Below are OIDC specific. Just ignore if OAuth2
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
        _sinfo = _context.sdb[sid]

        if request.get("scope"):
            aresp["scope"] = request["scope"]

        rtype = set(request["response_type"][:])
        handled_response_type = []

        fragment_enc = True
        if len(rtype) == 1 and "code" in rtype:
            fragment_enc = False

        if "code" in request["response_type"]:
            _code = aresp["code"] = _context.sdb[sid]["code"]
            handled_response_type.append("code")
        else:
            _context.sdb.update(sid, code=None)
            _code = None

        if "token" in rtype:
            _dic = _context.sdb.upgrade_to_token(issue_refresh=False, key=sid)

            logger.debug("_dic: %s" % sanitize(_dic))
            for key, val in _dic.items():
                if key in aresp.parameters() and val is not None:
                    aresp[key] = val

            handled_response_type.append("token")

        _access_token = aresp.get("access_token", None)

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
