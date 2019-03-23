import json
import logging
import time
from urllib.parse import parse_qs
from urllib.parse import splitquery
from urllib.parse import unquote
from urllib.parse import urlparse

from cryptojwt import BadSyntax
from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64d
from oidcmsg import oidc
from oidcmsg.exception import ParameterError
from oidcmsg.exception import URIError
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import verified_claim_name
from oidcservice.exception import InvalidRequest

from oidcendpoint import rndstr
from oidcendpoint import sanitize
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.cookie import append_cookie
from oidcendpoint.cookie import compute_session_state
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.exception import NoSuchAuthentication
from oidcendpoint.exception import RedirectURIError
from oidcendpoint.exception import TamperAllert
from oidcendpoint.exception import ToOld
from oidcendpoint.exception import UnknownClient
from oidcendpoint.session import setup_session
from oidcendpoint.user_authn.authn_context import pick_auth
from oidcendpoint.util import new_cookie

logger = logging.getLogger(__name__)

FORM_POST = """<html>
  <head>
    <title>Submit This Form</title>
  </head>
  <body onload="javascript:document.forms[0].submit()">
    <form method="post" action={action}>
        {inputs}
    </form>
  </body>
</html>"""


def inputs(form_args):
    """
    Creates list of input elements
    """
    element = []
    for name, value in form_args.items():
        element.append(
            '<input type="hidden" name="{}" value="{}"/>'.format(name, value))
    return "\n".join(element)


def max_age(request):
    try:
        return request[verified_claim_name("request")]["max_age"]
    except KeyError:
        try:
            return request["max_age"]
        except KeyError:
            return 0


def re_authenticate(request, authn):
    if "prompt" in request and "login" in request["prompt"]:
        if authn.done(request):
            return True

    return False


def acr_claims(request):
    try:
        acrdef = request["claims"]["id_token"]["acr"]
    except KeyError:
        return None
    else:
        if isinstance(acrdef, dict):
            try:
                return [acrdef["value"]]
            except KeyError:
                try:
                    return acrdef["values"]
                except KeyError:
                    pass

    return None


def verify_uri(endpoint_context, request, uri_type, client_id=None):
    """
    A redirect URI
    MUST NOT contain a fragment
    MAY contain query component

    :param endpoint_context:
    :param request:
    :param uri_type:
    :return: An error response if the redirect URI is faulty otherwise
        None
    """
    try:
        _cid = request["client_id"]
    except KeyError:
        _cid = client_id

    if not _cid:
        logger.error('No client id found')
        raise UnknownClient('No client_id provided')

    try:
        _redirect_uri = unquote(request[uri_type])

        part = urlparse(_redirect_uri)
        if part.fragment:
            raise URIError("Contains fragment")

        (_base, _query) = splitquery(_redirect_uri)
        if _query:
            _query = parse_qs(_query)

        match = False
        for regbase, rquery in endpoint_context.cdb[_cid]['{}s'.format(uri_type)]:
            # The URI MUST exactly match one of the Redirection URI
            if _base == regbase:
                # every registered query component must exist in the uri
                if rquery:
                    for key, vals in rquery.items():
                        assert key in _query
                        for val in vals:
                            assert val in _query[key]
                # and vice versa, every query component in the uri
                # must be registered
                if _query:
                    if rquery is None:
                        raise ValueError
                    for key, vals in _query.items():
                        assert key in rquery
                        for val in vals:
                            assert val in rquery[key]
                match = True
                break
        if not match:
            raise RedirectURIError("Doesn't match any registered uris")

    except Exception:
        try:
            _cinfo = endpoint_context.cdb[str(_cid)]
        except KeyError:
            raise ValueError('Unknown client: {}'.format(_cid))
        else:
            logger.info("Registered {}s: {}".format(uri_type, sanitize(_cinfo)))
            raise RedirectURIError(
                "Faulty {}: {}".format(uri_type, request[uri_type]))


def join_query(base, queryp):
    if queryp:
        return '{}?{}'.format(base, queryp)
    else:
        return base


def get_uri(endpoint_context, request, uri_type):
    """ verify that the redirect URI is reasonable

    :param endpoint_context:
    :param request: The Authorization request
    :param uri_type: 'redirect_uri' or 'post_logout_redirect_uri'
    :return: redirect_uri
    """
    if uri_type in request:
        verify_uri(endpoint_context, request, uri_type)
        uri = request[uri_type]
    else:
        try:
            _specs = endpoint_context.cdb[
                str(request["client_id"])]["{}s".format(uri_type)]
        except KeyError:
            raise ParameterError(
                "Missing {} and none registered".format(uri_type))
        else:
            if len(_specs) > 1:
                raise ParameterError(
                    "Missing {} and more than one registered".format(uri_type))
            else:
                uri = join_query(*_specs[0])

    return uri


def authn_args_gather(request, authn_class_ref, cinfo, **kwargs):
    # gather information to be used by the authentication method
    authn_args = {
        "authn_class_ref": authn_class_ref,
        "query": request.to_urlencoded(),
        'return_uri': request['redirect_uri']
    }

    if "req_user" in kwargs:
        authn_args["as_user"] = kwargs["req_user"],

    for attr in ["policy_uri", "logo_uri", "tos_uri"]:
        try:
            authn_args[attr] = cinfo[attr]
        except KeyError:
            pass

    for attr in ["ui_locales", "acr_values"]:
        try:
            authn_args[attr] = request[attr]
        except KeyError:
            pass

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
    try:
        aresp["state"] = request["state"]
    except KeyError:
        pass

    if "response_type" in request and request["response_type"] == ["none"]:
        fragment_enc = False
    else:
        _context = endpoint.endpoint_context
        _sinfo = _context.sdb[sid]

        try:
            aresp["scope"] = request["scope"]
        except KeyError:
            pass

        rtype = set(request["response_type"][:])
        handled_response_type = []
        if len(rtype) == 1 and "code" in rtype:
            fragment_enc = False
        else:
            fragment_enc = True

        if "code" in request["response_type"]:
            _code = aresp["code"] = _context.sdb[sid]["code"]
            handled_response_type.append("code")
        else:
            _context.sdb.update(sid, code=None)
            _code = None

        if "token" in rtype:
            _dic = _context.sdb.upgrade_to_token(issue_refresh=False,
                                                 key=sid)

            logger.debug("_dic: %s" % sanitize(_dic))
            for key, val in _dic.items():
                if key in aresp.parameters() and val is not None:
                    aresp[key] = val

            handled_response_type.append("token")

        try:
            _access_token = aresp["access_token"]
        except KeyError:
            _access_token = None

        if "id_token" in request["response_type"]:
            kwargs = {}
            if {'code', 'id_token', 'token'}.issubset(rtype):
                kwargs = {"code": _code, "access_token": _access_token}
            elif {'code', 'id_token'}.issubset(rtype):
                kwargs = {"code": _code}
            elif {'id_token', 'token'}.issubset(rtype):
                kwargs = {"access_token": _access_token}

            if request["response_type"] == ["id_token"]:
                kwargs['user_claims'] = True

            try:
                id_token = _context.idtoken.make(request, _sinfo, **kwargs)
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = AuthorizationErrorResponse(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token")
                return {'response_args': resp, 'fragment_enc': fragment_enc}

            aresp["id_token"] = id_token
            _sinfo["id_token"] = id_token
            handled_response_type.append("id_token")

        not_handled = rtype.difference(handled_response_type)
        if not_handled:
            resp = AuthorizationErrorResponse(
                error="invalid_request",
                error_description="unsupported_response_type")
            return {'response_args': resp, 'fragment_enc': fragment_enc}

    return {'response_args': aresp, 'fragment_enc': fragment_enc}


def proposed_user(request):
    try:
        return request[verified_claim_name('it_token_hint')]['sub']
    except KeyError:
        return ''


class Authorization(Endpoint):
    request_cls = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    request_format = 'urlencoded'
    response_format = 'urlencoded'
    response_placement = 'url'
    endpoint_name = 'authorization_endpoint'

    def __init__(self, endpoint_context, **kwargs):
        Endpoint.__init__(self, endpoint_context, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._post_parse_request)

    def filter_request(self, endpoint_context, req):
        return req

    def verify_response_type(self, request, cinfo):
        # Checking response types
        try:
            _registered = [set(rt.split(' ')) for rt in cinfo['response_types']]
        except KeyError:
            # If no response_type is registered by the client then we'll
            # code which it the default according to the OIDC spec.
            _registered = [{'code'}]

        # Is the asked for response_type among those that are permitted
        return set(request["response_type"]) in _registered

    def _post_parse_request(self, request, client_id, endpoint_context,
                            **kwargs):
        """

        :param endpoint_context:
        :param request:
        :param client_id:
        :param kwargs:
        :return:
        """
        if not request:
            logger.debug("No AuthzRequest")
            return AuthorizationErrorResponse(
                error="invalid_request",
                error_description="Can not parse AuthzRequest")

        request = self.filter_request(endpoint_context, request)

        try:
            _cinfo = endpoint_context.cdb[client_id]
        except KeyError:
            logger.error(
                'Client ID ({}) not in client database'.format(
                    request['client_id']))
            return AuthorizationErrorResponse(
                error='unauthorized_client', error_description='unknown client')

        # Is the asked for response_type among those that are permitted
        if not self.verify_response_type(request, _cinfo):
            return AuthorizationErrorResponse(
                error="invalid_request",
                error_description="Trying to use unregistered response_typ")

        # Get the redirect URI
        try:
            redirect_uri = get_uri(endpoint_context, request, 'redirect_uri')
        except (RedirectURIError, ParameterError, UnknownClient) as err:
            return AuthorizationErrorResponse(
                error="invalid_request",
                error_description="{}:{}".format(err.__class__.__name__, err))
        else:
            request['redirect_uri'] = redirect_uri

        return request

    def pick_authn_method(self, request, redirect_uri, acr=None):
        """
        Which ACR (Authentication context class reference) to use can
        either be specified in the request, more specifically in the claims
        parameter or in the call to this method.

        :param request: The authorization/authentication request
        :param redirect_uri: Where the auth response should be returned to.
        :param acr: Authentication context class reference
        :return: 
        """
        _context = self.endpoint_context
        acrs = acr_claims(request)
        if acrs == [] and acr:
            acrs = [acr]

        if acrs:
            # If acr claims are present the picked acr value MUST match
            # one of the given
            tup = (None, None)
            for acr in acrs:
                res = _context.authn_broker.pick(acr, "exact")
                logger.debug("Picked AuthN broker for ACR %s: %s" % (
                    str(acr), str(res)))
                if res:  # Return the best guess by pick.
                    tup = res[0]
                    break
            authn, authn_class_ref = tup
        else:
            authn, authn_class_ref = pick_auth(_context, request)
            if not authn:
                authn, authn_class_ref = pick_auth(_context, request, "better")
                if not authn:
                    authn, authn_class_ref = pick_auth(_context, request, "any")

        if authn is None:
            return {'error': "access_denied", 'return_uri': redirect_uri,
                    'return_type': request["response_type"]}
        else:
            logger.info('Authentication class: {}, acr: {}'.format(
                authn.__class__.__name__, authn_class_ref))

        return authn, authn_class_ref

    def setup_auth(self, request, redirect_uri, cinfo, cookie, acr=None,
                   **kwargs):
        """

        :param request: The authorization/authentication request
        :param redirect_uri:
        :param cinfo: client info
        :param cookie:
        :param acr: Default ACR, if nothing else is specified
        :param kwargs:
        :return:
        """

        try:
            auth_id = kwargs['auth_method_id']
        except KeyError:
            _res = self.pick_authn_method(request, redirect_uri, acr)
        else:
            _res = self.endpoint_context.authn_broker.get_method_by_id(auth_id)

        if isinstance(_res, dict):  # error message
            return _res
        else:
            authn, authn_class_ref = _res

        try:
            try:
                _auth_info = kwargs["authn"]
            except KeyError:
                _auth_info = ""

            if "upm_answer" in request and request["upm_answer"] == "true":
                _max_age = 0
            else:
                _max_age = max_age(request)

            identity, _ts = authn.authenticated_as(
                cookie, authorization=_auth_info, max_age=_max_age)
        except (NoSuchAuthentication, TamperAllert):
            identity = None
            _ts = 0
        except ToOld:
            logger.info("Too old authentication")
            identity = None
            _ts = 0
        else:
            if identity:
                try:
                    _id = b64d(as_bytes(identity['uid']))
                except BadSyntax:
                    pass
                else:
                    _info = json.loads(as_unicode(_id))

                    try:
                        session = self.endpoint_context.sdb[_info['sid']]
                    except KeyError:
                        identity = None
                    else:
                        if session is None:
                            identity = None
                        elif 'revoked' in session:
                            identity = None

        authn_args = authn_args_gather(request, authn_class_ref, cinfo,
                                       **kwargs)

        # To authenticate or Not
        if identity is None:  # No!
            logger.info("No active authentication")
            if "prompt" in request and "none" in request["prompt"]:
                # Need to authenticate but not allowed
                return {
                    'error': "login_required", 'return_uri': redirect_uri,
                    'return_type': request["response_type"]
                }
            else:
                return {'function': authn, 'args': authn_args}
        else:
            logger.info("Active authentication")
            if re_authenticate(request, authn):
                # demand re-authentication
                return {'function': authn, 'args': authn_args}
            else:
                # I get back a dictionary
                user = identity["uid"]
                if "req_user" in kwargs:
                    sids = self.endpoint_context.sdb.get_sids_by_sub(
                        kwargs["req_user"])
                    if sids and user != \
                            self.endpoint_context.sdb.get_authentication_event(
                                sids[-1]).uid:
                        logger.debug("Wanted to be someone else!")
                        if "prompt" in request and "none" in request["prompt"]:
                            # Need to authenticate but not allowed
                            return {
                                'error': "login_required",
                                'return_uri': redirect_uri
                            }
                        else:
                            return {'function': authn, 'args': authn_args}

        authn_event = create_authn_event(identity["uid"],
                                         identity.get('salt', ''),
                                         authn_info=authn_class_ref,
                                         time_stamp=_ts)
        try:
            authn_event['valid_until'] = time.time()+authn.kwargs['expires_in']
        except KeyError:
            pass

        return {"authn_event": authn_event, "identity": identity, "user": user}

    def aresp_check(self, aresp, request):
        return ""

    def response_mode(self, request, **kwargs):
        resp_mode = request["response_mode"]
        if resp_mode == "form_post":
            msg = FORM_POST.format(
                inputs=inputs(kwargs["response_args"].to_dict()),
                action=kwargs["return_uri"])
            kwargs['response_msg'] = msg
            return kwargs
        elif resp_mode == 'fragment' and not kwargs['fragment_enc']:
            # Can't be done
            raise InvalidRequest("wrong response_mode")
        elif resp_mode == 'query' and kwargs['fragment_enc']:
            # Can't be done
            raise InvalidRequest("wrong response_mode")
        else:
            raise InvalidRequest("Unknown response_mode")

    def error_response(self, response_info, error, error_description):
        resp = AuthorizationErrorResponse(
            error=error, error_description=error_description)
        response_info['response_args'] = resp
        return response_info

    def post_authentication(self, user, request, sid, **kwargs):
        """
        Things that are done after a successful authentication.

        :param user:
        :param request:
        :param sid:
        :param kwargs:
        :return: A dictionary with 'response_args'
        """

        response_info = {}

        # Do the authorization
        try:
            permission = self.endpoint_context.authz(
                user, client_id=request['client_id'])
        except ToOld as err:
            return self.error_response(
                response_info, 'access_denied',
                'Authentication to old {}'.format(err.args))
        except Exception as err:
            return self.error_response(response_info, 'access_denied',
                                       '{}'.format(err.args))
        else:
            try:
                self.endpoint_context.sdb.update(sid, permission=permission)
            except Exception as err:
                return self.error_response(response_info, 'server_error',
                                           '{}'.format(err.args))

        logger.debug("response type: %s" % request["response_type"])

        if self.endpoint_context.sdb.is_session_revoked(sid):
            return self.error_response(response_info, "access_denied",
                                       "Session is revoked")

        response_info = create_authn_response(self, request, sid)

        try:
            redirect_uri = get_uri(self.endpoint_context, request, 'redirect_uri')
        except (RedirectURIError, ParameterError) as err:
            return self.error_response(response_info,
                                       'invalid_request',
                                       '{}'.format(err.args))
        else:
            response_info['return_uri'] = redirect_uri

        # Must not use HTTP unless implicit grant type and native application
        # info = self.aresp_check(response_info['response_args'], request)
        # if isinstance(info, ResponseMessage):
        #     return info

        _cookie = new_cookie(
            self.endpoint_context, sub=user, sid=sid, state=request['state'],
            client_id=request['client_id'],
            cookie_name=self.endpoint_context.cookie_name['session'])

        # Now about the response_mode. Should not be set if it's obvious
        # from the response_type. Knows about 'query', 'fragment' and
        # 'form_post'.

        if "response_mode" in request:
            try:
                response_info = self.response_mode(request, **response_info)
            except InvalidRequest as err:
                return self.error_response(response_info,
                                           'invalid_request',
                                           '{}'.format(err.args))

        response_info['cookie'] = [_cookie]

        return response_info

    def authz_part2(self, user, authn_event, request, **kwargs):
        """
        After the authentication this is where you should end up

        :param user:
        :param request: The Authorization Request
        :param sid: Session key
        :param kwargs: possible other parameters
        :return: A redirect to the redirect_uri of the client
        """
        sid = setup_session(self.endpoint_context, request, user,
                            authn_event=authn_event)

        try:
            resp_info = self.post_authentication(user, request, sid, **kwargs)
        except Exception as err:
            return self.error_response({}, 'server_error', err)

        if "check_session_iframe" in self.endpoint_context.provider_info:
            ec = self.endpoint_context
            salt = rndstr()
            if ec.sdb.is_session_revoked(sid):
                pass
            else:
                authn_event = ec.sdb.get_authentication_event(sid)  # use the last session
                _state = json.dumps({'authn_time': authn_event['authn_time']})

                session_cookie = ec.cookie_dealer.create_cookie(
                    json.dumps(_state), typ="session",
                    cookie_name=ec.cookie_name['session_management'])

                opbs = session_cookie[ec.cookie_name['session_management']]

                _session_state = compute_session_state(opbs.value, salt,
                                                       request["client_id"],
                                                       resp_info['return_uri'])

                if 'cookie' in resp_info:
                    if isinstance(resp_info['cookie'], list):
                        resp_info['cookie'].append(session_cookie)
                    else:
                        append_cookie(resp_info['cookie'], session_cookie)
                else:
                    resp_info['cookie'] = session_cookie

                resp_info['response_args']['session_state'] = _session_state

        # Mix-Up mitigation
        resp_info['response_args']['iss'] = self.endpoint_context.issuer
        resp_info['response_args']['client_id'] = request['client_id']

        return resp_info

    def process_request(self, request_info=None, **kwargs):
        """ The AuthorizationRequest endpoint

        :param request_info: The authorization request as a dictionary
        :return: dictionary
        """

        if isinstance(request_info, AuthorizationErrorResponse):
            return request_info

        _cid = request_info["client_id"]
        cinfo = self.endpoint_context.cdb[_cid]
        try:
            cookie = kwargs['cookie']
        except KeyError:
            cookie = ''
        else:
            del kwargs['cookie']

        if proposed_user(request_info):
            kwargs['req_user'] = proposed_user(request_info)

        info = self.setup_auth(request_info, request_info["redirect_uri"],
                               cinfo, cookie, **kwargs)

        if 'error' in info:
            return info

        try:
            _function = info['function']
        except KeyError:  # already authenticated
            logger.debug("- authenticated -")
            logger.debug("AREQ keys: %s" % request_info.keys())

            res = self.authz_part2(info['user'], info['authn_event'],
                                   request_info, cookie=cookie)

            return res
        else:
            try:
                # Run the authentication function
                return {
                    'http_response': _function(**info['args']),
                    'return_uri': request_info["redirect_uri"]
                }
            except Exception as err:
                logger.exception(err)
                return {'http_response': 'Internal error: {}'.format(err)}
