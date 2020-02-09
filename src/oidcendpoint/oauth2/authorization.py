import json
import logging
import time

from cryptojwt import BadSyntax
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64d
from cryptojwt.utils import b64e
from oidcmsg import oauth2
from oidcmsg.exception import ParameterError
from oidcmsg.oauth2 import AuthorizationErrorResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import verified_claim_name

from oidcendpoint import rndstr
from oidcendpoint import sanitize
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.common.authorization import AllowedAlgorithms
from oidcendpoint.common.authorization import DEFAULT_SCOPES
from oidcendpoint.common.authorization import FORM_POST
from oidcendpoint.common.authorization import authn_args_gather
from oidcendpoint.common.authorization import get_uri
from oidcendpoint.common.authorization import inputs
from oidcendpoint.common.authorization import max_age
from oidcendpoint.cookie import append_cookie
from oidcendpoint.cookie import compute_session_state
from oidcendpoint.cookie import new_cookie
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.exception import InvalidRequest
from oidcendpoint.exception import NoSuchAuthentication
from oidcendpoint.exception import RedirectURIError
from oidcendpoint.exception import ServiceError
from oidcendpoint.exception import TamperAllert
from oidcendpoint.exception import ToOld
from oidcendpoint.exception import UnknownClient
from oidcendpoint.session import setup_session
from oidcendpoint.user_authn.authn_context import pick_auth

logger = logging.getLogger(__name__)


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


# For the time being. This is JAR specific and should probably be configurable.
ALG_PARAMS = {
    "sign": [
        "request_object_signing_alg",
        "request_object_signing_alg_values_supported",
    ],
    "enc_alg": [
        "request_object_encryption_alg",
        "request_object_encryption_alg_values_supported",
    ],
    "enc_enc": [
        "request_object_encryption_enc",
        "request_object_encryption_enc_values_supported",
    ],
}


def re_authenticate(request, authn):
    return False


class Authorization(Endpoint):
    request_cls = oauth2.AuthorizationRequest
    response_cls = oauth2.AuthorizationResponse
    request_format = "urlencoded"
    response_format = "urlencoded"
    response_placement = "url"
    endpoint_name = "authorization_endpoint"
    name = "authorization"
    default_capabilities = {
        "claims_parameter_supported": True,
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "response_types_supported": ["code", "token", "code token"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "request_object_signing_alg_values_supported": None,
        "request_object_encryption_alg_values_supported": None,
        "request_object_encryption_enc_values_supported": None,
        "grant_types_supported": ["authorization_code", "implicit"],
        "scopes_supported": DEFAULT_SCOPES,
    }

    def __init__(self, endpoint_context, **kwargs):
        Endpoint.__init__(self, endpoint_context, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._do_request_uri)
        self.post_parse_request.append(self._post_parse_request)
        self.allowed_request_algorithms = AllowedAlgorithms(ALG_PARAMS)

    def filter_request(self, endpoint_context, req):
        return req

    def verify_response_type(self, request, cinfo):
        # Checking response types
        _registered = [set(rt.split(" ")) for rt in cinfo.get("response_types", [])]
        if not _registered:
            # If no response_type is registered by the client then we'll
            # code which it the default according to the OIDC spec.
            _registered = [{"code"}]

        # Is the asked for response_type among those that are permitted
        return set(request["response_type"]) in _registered

    def _do_request_uri(self, request, client_id, endpoint_context, **kwargs):
        _request_uri = request.get("request_uri")
        if _request_uri:
            # Do I do pushed authorization requests ?
            if "pushed_authorization" in endpoint_context.endpoint:
                # Is it a UUID urn
                if _request_uri.startswith("urn:uuid:"):
                    _req = endpoint_context.par_db.get(_request_uri)
                    if _req:
                        del endpoint_context.par_db[_request_uri]  # One time usage
                        return _req
                    else:
                        raise ValueError("Got a request_uri I can not resolve")

            # Do I support request_uri ?
            _supported = endpoint_context.provider_info.get(
                "request_uri_parameter_supported", True
            )
            _registered = endpoint_context.cdb[client_id].get("request_uris")
            # Not registered should be handled else where
            if _registered:
                # Before matching remove a possible fragment
                _p = _request_uri.split("#")
                if _p[0] not in _registered:
                    raise ValueError("A request_uri outside the registered")
            # Fetch the request
            _resp = endpoint_context.httpc.get(_request_uri,
                                               **endpoint_context.httpc_params)
            if _resp.status_code == 200:
                args = {"keyjar": endpoint_context.keyjar}
                request = AuthorizationRequest().from_jwt(_resp.text, **args)
                self.allowed_request_algorithms(
                    client_id,
                    endpoint_context,
                    request.jws_header.get("alg", "RS256"),
                    "sign",
                )
                if request.jwe_header is not None:
                    self.allowed_request_algorithms(
                        client_id,
                        endpoint_context,
                        request.jws_header.get("alg"),
                        "enc_alg",
                    )
                    self.allowed_request_algorithms(
                        client_id,
                        endpoint_context,
                        request.jws_header.get("enc"),
                        "enc_enc",
                    )
                request[verified_claim_name("request")] = request
            else:
                raise ServiceError("Got a %s response", _resp.status)

        return request

    def _post_parse_request(self, request, client_id, endpoint_context, **kwargs):
        """
        Verify the authorization request.

        :param endpoint_context:
        :param request:
        :param client_id:
        :param kwargs:
        :return:
        """
        if not request:
            logger.debug("No AuthzRequest")
            return AuthorizationErrorResponse(
                error="invalid_request", error_description="Can not parse AuthzRequest"
            )

        request = self.filter_request(endpoint_context, request)

        _cinfo = endpoint_context.cdb.get(client_id)
        if not _cinfo:
            logger.error(
                "Client ID ({}) not in client database".format(request["client_id"])
            )
            return AuthorizationErrorResponse(
                error="unauthorized_client", error_description="unknown client"
            )

        # Is the asked for response_type among those that are permitted
        if not self.verify_response_type(request, _cinfo):
            return AuthorizationErrorResponse(
                error="invalid_request",
                error_description="Trying to use unregistered response_type",
            )

        # Get a verified redirect URI
        try:
            redirect_uri = get_uri(endpoint_context, request, "redirect_uri")
        except (RedirectURIError, ParameterError, UnknownClient) as err:
            return AuthorizationErrorResponse(
                error="invalid_request",
                error_description="{}:{}".format(err.__class__.__name__, err),
            )
        else:
            request["redirect_uri"] = redirect_uri

        return request

    def pick_authn_method(self, request, redirect_uri, acr=None, **kwargs):
        auth_id = kwargs.get("auth_method_id")
        if auth_id:
            return self.endpoint_context.authn_broker[auth_id]

        if acr:
            res = self.endpoint_context.authn_broker.pick(acr)
        else:
            res = pick_auth(self.endpoint_context, request)

        if res:
            return res
        else:
            return {
                "error": "access_denied",
                "error_description": "ACR I do not support",
                "return_uri": redirect_uri,
                "return_type": request["response_type"],
            }

    def setup_auth(self, request, redirect_uri, cinfo, cookie, acr=None, **kwargs):
        """

        :param request: The authorization/authentication request
        :param redirect_uri:
        :param cinfo: client info
        :param cookie:
        :param acr: Default ACR, if nothing else is specified
        :param kwargs:
        :return:
        """

        res = self.pick_authn_method(request, redirect_uri, acr, **kwargs)

        authn = res["method"]
        authn_class_ref = res["acr"]

        try:
            _auth_info = kwargs.get("authn", "")
            if "upm_answer" in request and request["upm_answer"] == "true":
                _max_age = 0
            else:
                _max_age = max_age(request)

            identity, _ts = authn.authenticated_as(
                cookie, authorization=_auth_info, max_age=_max_age
            )
        except (NoSuchAuthentication, TamperAllert):
            identity = None
            _ts = 0
        except ToOld:
            logger.info("Too old authentication")
            identity = None
            _ts = 0
        else:
            if identity:
                try:  # If identity['uid'] is in fact a base64 encoded JSON string
                    _id = b64d(as_bytes(identity["uid"]))
                except BadSyntax:
                    pass
                else:
                    identity = json.loads(as_unicode(_id))

                    session = self.endpoint_context.sdb[identity.get("sid")]
                    if not session or "revoked" in session:
                        identity = None

        authn_args = authn_args_gather(request, authn_class_ref, cinfo, **kwargs)

        # To authenticate or Not
        if identity is None:  # No!
            logger.info("No active authentication")
            if "prompt" in request and "none" in request["prompt"]:
                # Need to authenticate but not allowed
                return {
                    "error": "login_required",
                    "return_uri": redirect_uri,
                    "return_type": request["response_type"],
                }
            else:
                return {"function": authn, "args": authn_args}
        else:
            logger.info("Active authentication")
            if re_authenticate(request, authn):
                # demand re-authentication
                return {"function": authn, "args": authn_args}
            else:
                # I get back a dictionary
                user = identity["uid"]
                if "req_user" in kwargs:
                    sids = self.endpoint_context.sdb.get_sids_by_sub(kwargs["req_user"])
                    if (
                        sids
                        and user
                        != self.endpoint_context.sdb.get_authentication_event(
                            sids[-1]
                        ).uid
                    ):
                        logger.debug("Wanted to be someone else!")
                        if "prompt" in request and "none" in request["prompt"]:
                            # Need to authenticate but not allowed
                            return {
                                "error": "login_required",
                                "return_uri": redirect_uri,
                            }
                        else:
                            return {"function": authn, "args": authn_args}

        authn_event = create_authn_event(
            identity["uid"],
            identity.get("salt", ""),
            authn_info=authn_class_ref,
            time_stamp=_ts,
        )
        if "valid_until" in authn_event:
            vu = time.time() + authn.kwargs.get("expires_in", 0.0)
            authn_event["valid_until"] = vu

        return {"authn_event": authn_event, "identity": identity, "user": user}

    def aresp_check(self, aresp, request):
        return ""

    def response_mode(self, request, **kwargs):
        resp_mode = request["response_mode"]
        if resp_mode == "form_post":
            msg = FORM_POST.format(
                inputs=inputs(kwargs["response_args"].to_dict()),
                action=kwargs["return_uri"],
            )
            kwargs.update({
                "response_msg": msg,
                "content_type": 'text/html',
                "response_placement": "body"
            })
        elif resp_mode == "fragment":
            if "fragment_enc" in kwargs:
                if not kwargs["fragment_enc"]:
                    # Can't be done
                    raise InvalidRequest("wrong response_mode")
            else:
                kwargs["fragment_enc"] = True
        elif resp_mode == "query":
            if "fragment_enc" in kwargs:
                if kwargs["fragment_enc"]:
                    # Can't be done
                    raise InvalidRequest("wrong response_mode")
        else:
            raise InvalidRequest("Unknown response_mode")
        return kwargs

    def error_response(self, response_info, error, error_description):
        resp = AuthorizationErrorResponse(
            error=error, error_description=error_description
        )
        response_info["response_args"] = resp
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
                user, client_id=request["client_id"]
            )
        except ToOld as err:
            return self.error_response(
                response_info,
                "access_denied",
                "Authentication to old {}".format(err.args),
            )
        except Exception as err:
            return self.error_response(
                response_info, "access_denied", "{}".format(err.args)
            )
        else:
            try:
                self.endpoint_context.sdb.update(sid, permission=permission)
            except Exception as err:
                return self.error_response(
                    response_info, "server_error", "{}".format(err.args)
                )

        logger.debug("response type: %s" % request["response_type"])

        if self.endpoint_context.sdb.is_session_revoked(sid):
            return self.error_response(
                response_info, "access_denied", "Session is revoked"
            )

        response_info = create_authn_response(self, request, sid)

        try:
            redirect_uri = get_uri(self.endpoint_context, request, "redirect_uri")
        except (RedirectURIError, ParameterError) as err:
            return self.error_response(
                response_info, "invalid_request", "{}".format(err.args)
            )
        else:
            response_info["return_uri"] = redirect_uri

        # Must not use HTTP unless implicit grant type and native application
        # info = self.aresp_check(response_info['response_args'], request)
        # if isinstance(info, ResponseMessage):
        #     return info

        _cookie = new_cookie(
            self.endpoint_context,
            sub=user,
            sid=sid,
            state=request["state"],
            client_id=request["client_id"],
            cookie_name=self.endpoint_context.cookie_name["session"],
        )

        # Now about the response_mode. Should not be set if it's obvious
        # from the response_type. Knows about 'query', 'fragment' and
        # 'form_post'.

        if "response_mode" in request:
            try:
                response_info = self.response_mode(request, **response_info)
            except InvalidRequest as err:
                return self.error_response(
                    response_info, "invalid_request", "{}".format(err.args)
                )

        response_info["cookie"] = [_cookie]

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
        sid = setup_session(
            self.endpoint_context, request, user, authn_event=authn_event
        )

        try:
            resp_info = self.post_authentication(user, request, sid, **kwargs)
        except Exception as err:
            return self.error_response({}, "server_error", err)

        if "check_session_iframe" in self.endpoint_context.provider_info:
            ec = self.endpoint_context
            salt = rndstr()
            if not ec.sdb.is_session_revoked(sid):
                authn_event = ec.sdb.get_authentication_event(
                    sid
                )  # use the last session
                _state = b64e(
                    as_bytes(json.dumps({"authn_time": authn_event["authn_time"]}))
                )

                session_cookie = ec.cookie_dealer.create_cookie(
                    as_unicode(_state),
                    typ="session",
                    cookie_name=ec.cookie_name["session_management"],
                )

                opbs = session_cookie[ec.cookie_name["session_management"]]

                logger.debug(
                    "compute_session_state: client_id=%s, origin=%s, opbs=%s, salt=%s",
                    request["client_id"],
                    resp_info["return_uri"],
                    opbs.value,
                    salt,
                )

                _session_state = compute_session_state(
                    opbs.value, salt, request["client_id"], resp_info["return_uri"]
                )

                if "cookie" in resp_info:
                    if isinstance(resp_info["cookie"], list):
                        resp_info["cookie"].append(session_cookie)
                    else:
                        append_cookie(resp_info["cookie"], session_cookie)
                else:
                    resp_info["cookie"] = session_cookie

                resp_info["response_args"]["session_state"] = _session_state

        # Mix-Up mitigation
        resp_info["response_args"]["iss"] = self.endpoint_context.issuer
        resp_info["response_args"]["client_id"] = request["client_id"]

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

        cookie = kwargs.get("cookie", "")
        if cookie:
            del kwargs["cookie"]

        info = self.setup_auth(
            request_info, request_info["redirect_uri"], cinfo, cookie, **kwargs
        )

        if "error" in info:
            return info

        _function = info.get("function")
        if not _function:
            logger.debug("- authenticated -")
            logger.debug("AREQ keys: %s" % request_info.keys())
            res = self.authz_part2(
                info["user"], info["authn_event"], request_info, cookie=cookie
            )
            return res

        try:
            # Run the authentication function
            return {
                "http_response": _function(**info["args"]),
                "return_uri": request_info["redirect_uri"],
            }
        except Exception as err:
            logger.exception(err)
            return {"http_response": "Internal error: {}".format(err)}
