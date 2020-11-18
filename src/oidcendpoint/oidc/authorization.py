import json
import logging
from urllib.parse import urlsplit

from cryptojwt import BadSyntax
from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64d
from cryptojwt.utils import b64e
from oidcmsg import oidc
from oidcmsg.exception import ParameterError
from oidcmsg.oidc import Claims
from oidcmsg.oidc import verified_claim_name
from oidcmsg.time_util import time_sans_frac

from oidcendpoint import rndstr
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.common.authorization import AllowedAlgorithms
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
from oidcendpoint.grant import get_usage_rules
from oidcendpoint.oauth2.authorization import check_unknown_scopes_policy
from oidcendpoint.session_management import ClientSessionInfo
from oidcendpoint.session_management import UserSessionInfo
from oidcendpoint.session_management import session_key
from oidcendpoint.session_management import unpack_session_key
from oidcendpoint.token_handler import UnknownToken
from oidcendpoint.user_authn.authn_context import pick_auth

logger = logging.getLogger(__name__)


def proposed_user(request):
    cn = verified_claim_name("it_token_hint")
    if request.get(cn):
        return request[cn].get("sub", "")
    return ""


def acr_claims(request):
    acrdef = None

    _claims = request.get("claims")
    if isinstance(_claims, str):
        _claims = Claims().from_json(_claims)

    if _claims:
        _id_token_claim = _claims.get("id_token")
        if _id_token_claim:
            acrdef = _id_token_claim.get("acr")

    if isinstance(acrdef, dict):
        if acrdef.get("value"):
            return [acrdef["value"]]
        elif acrdef.get("values"):
            return acrdef["values"]


def host_component(url):
    res = urlsplit(url)
    return "{}://{}".format(res.scheme, res.netloc)


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
    if "prompt" in request and "login" in request["prompt"]:
        if authn.done(request):
            return True

    return False


class Authorization(Endpoint):
    request_cls = oidc.AuthorizationRequest
    response_cls = oidc.AuthorizationResponse
    error_cls = oidc.AuthorizationErrorResponse
    request_format = "urlencoded"
    response_format = "urlencoded"
    response_placement = "url"
    endpoint_name = "authorization_endpoint"
    name = "authorization"
    default_capabilities = {
        "claims_parameter_supported": True,
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "id_token token",
            "code id_token token",
        ],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "request_object_signing_alg_values_supported": None,
        "request_object_encryption_alg_values_supported": None,
        "request_object_encryption_enc_values_supported": None,
        "grant_types_supported": ["authorization_code", "implicit"],
        "claim_types_supported": ["normal", "aggregated", "distributed"],
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
                        del endpoint_context.par_db[_request_uri]  # One time
                        # usage
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
                # ignore registered fragments for now.
                if _p[0] not in [l[0] for l in _registered]:
                    raise ValueError("A request_uri outside the registered")

            # Fetch the request
            _resp = endpoint_context.httpc.get(
                _request_uri, **endpoint_context.httpc_params
            )
            if _resp.status_code == 200:
                args = {"keyjar": endpoint_context.keyjar, "issuer": client_id}
                _ver_request = self.request_cls().from_jwt(_resp.text, **args)
                self.allowed_request_algorithms(
                    client_id,
                    endpoint_context,
                    _ver_request.jws_header.get("alg", "RS256"),
                    "sign",
                )
                if _ver_request.jwe_header is not None:
                    self.allowed_request_algorithms(
                        client_id,
                        endpoint_context,
                        _ver_request.jws_header.get("alg"),
                        "enc_alg",
                    )
                    self.allowed_request_algorithms(
                        client_id,
                        endpoint_context,
                        _ver_request.jws_header.get("enc"),
                        "enc_enc",
                    )
                # The protected info overwrites the non-protected
                for k, v in _ver_request.items():
                    request[k] = v

                request[verified_claim_name("request")] = _ver_request
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
            return self.error_cls(
                error="invalid_request", error_description="Can not parse AuthzRequest"
            )

        request = self.filter_request(endpoint_context, request)

        _cinfo = endpoint_context.cdb.get(client_id)
        if not _cinfo:
            logger.error(
                "Client ID ({}) not in client database".format(request["client_id"])
            )
            return self.error_cls(
                error="unauthorized_client", error_description="unknown client"
            )

        # Is the asked for response_type among those that are permitted
        if not self.verify_response_type(request, _cinfo):
            return self.error_cls(
                error="invalid_request",
                error_description="Trying to use unregistered response_type",
            )

        # Get a verified redirect URI
        try:
            redirect_uri = get_uri(endpoint_context, request, "redirect_uri")
        except (RedirectURIError, ParameterError, UnknownClient) as err:
            return self.error_cls(
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
        except UnknownToken:
            logger.info("Unknown Token")
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

        authn_args = authn_args_gather(request, authn_class_ref, cinfo, **kwargs)
        _mngr = self.endpoint_context.session_manager

        # To authenticate or Not
        if identity is None:  # No!
            logger.info("No active authentication")
            logger.debug(
                "Known clients: {}".format(list(self.endpoint_context.cdb.keys()))
            )

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
                    if user != kwargs["req_user"]:
                        logger.debug("Wanted to be someone else!")
                        if "prompt" in request and "none" in request["prompt"]:
                            # Need to authenticate but not allowed
                            return {
                                "error": "login_required",
                                "return_uri": redirect_uri,
                            }
                        else:
                            return {"function": authn, "args": authn_args}

                if "sid" in identity:
                    session_id = identity["sid"]
                    grant = _mngr[session_id]
                    if grant.is_active() is False:
                        return {"function": authn, "args": authn_args}

        authn_event = _mngr.get_authentication_event(user)

        if authn_event is None:
            authn_event = create_authn_event(
                identity["uid"],
                authn_info=authn_class_ref,
                time_stamp=_ts,
            )
            _mngr.set([identity["uid"]], UserSessionInfo(authentication_event=authn_event))

        _exp_in = authn.kwargs.get("expires_in")
        if _exp_in and "valid_until" in authn_event:
            authn_event["valid_until"] = utc_time_sans_frac() + _exp_in

        return {"authn_event": authn_event, "identity": identity, "user": user}

    def extra_response_args(self, aresp):
        return aresp

    def _mint_token(self, token_type, grant, session_info, based_on=None):
        _mngr = self.endpoint_context.session_manager
        usage_rules = get_usage_rules("authorization_code", self.endpoint_context,
                                      grant, session_info["client_id"])
        _exp_in = usage_rules.get("expires_in")
        if isinstance(_exp_in, str):
            _exp_in = int(_exp_in)

        token = grant.mint_token(
            token_type,
            value=_mngr.token_handler["access_token"](
                session_info["session_id"],
                client_id=session_info["client_id"],
                aud=grant.resources,
                user_claims=None,
                scope=grant.scope,
                sub=session_info["client_session_info"]['sub']
            ),
            based_on=based_on,
            usage_rules=usage_rules
        )

        if _exp_in:
            token.expires_at = utc_time_sans_frac() + _exp_in

        self.endpoint_context.session_manager.set(
            unpack_session_key(session_info["session_id"]), grant)

        return token

    def create_authn_response(self, request, sid):
        """

        :param self:
        :param request:
        :param sid:
        :return:
        """
        # create the response
        aresp = self.response_cls()
        if request.get("state"):
            aresp["state"] = request["state"]

        if "response_type" in request and request["response_type"] == ["none"]:
            fragment_enc = False
        else:
            _context = self.endpoint_context
            _mngr = self.endpoint_context.session_manager
            _sinfo = _mngr.get_session_info(sid)

            if request.get("scope"):
                aresp["scope"] = request["scope"]

            rtype = set(request["response_type"][:])
            handled_response_type = []

            fragment_enc = True
            if len(rtype) == 1 and "code" in rtype:
                fragment_enc = False

            grant = _sinfo["grant"]

            if "code" in request["response_type"]:
                _code = self._mint_token('authorization_code', grant, _sinfo)
                aresp["code"] = _code.value
                handled_response_type.append("code")
            else:
                _code = None

            if "token" in rtype:
                if _code:
                    based_on = _code
                else:
                    based_on = None

                _access_token = self._mint_token("access_token", grant, _sinfo, based_on)
                aresp['access_token'] = _access_token.value
                handled_response_type.append("token")
            else:
                _access_token = None

            if "id_token" in request["response_type"]:
                kwargs = {}
                if {"code", "id_token", "token"}.issubset(rtype):
                    kwargs = {"code": _code.value, "access_token": _access_token.value}
                elif {"code", "id_token"}.issubset(rtype):
                    kwargs = {"code": _code.value}
                elif {"id_token", "token"}.issubset(rtype):
                    kwargs = {"access_token": _access_token.value}

                # if request["response_type"] == ["id_token"]:
                #     kwargs["user_claims"] = True

                try:
                    id_token = _context.idtoken.make(sid, **kwargs)
                except (JWEException, NoSuitableSigningKeys) as err:
                    logger.warning(str(err))
                    resp = self.error_cls(
                        error="invalid_request",
                        error_description="Could not sign/encrypt id_token",
                    )
                    return {"response_args": resp, "fragment_enc": fragment_enc}

                aresp["id_token"] = id_token
                _mngr.update([_sinfo["user_id"], _sinfo["client_id"]],
                             {"id_token": id_token})
                handled_response_type.append("id_token")

            not_handled = rtype.difference(handled_response_type)
            if not_handled:
                resp = self.error_cls(
                    error="invalid_request", error_description="unsupported_response_type"
                )
                return {"response_args": resp, "fragment_enc": fragment_enc}

        aresp = self.extra_response_args(aresp)

        return {"response_args": aresp, "fragment_enc": fragment_enc}

    def aresp_check(self, aresp, request):
        return ""

    def response_mode(self, request, **kwargs):
        resp_mode = request["response_mode"]
        if resp_mode == "form_post":
            msg = FORM_POST.format(
                inputs=inputs(kwargs["response_args"].to_dict()),
                action=kwargs["return_uri"],
            )
            kwargs.update(
                {
                    "response_msg": msg,
                    "content_type": "text/html",
                    "response_placement": "body",
                }
            )
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
        resp = self.error_cls(
            error=error, error_description=str(error_description)
        )
        response_info["response_args"] = resp
        return response_info

    def post_authentication(self, user, request, pre_sid, **kwargs):
        """
        Things that are done after a successful authentication.

        :param user:
        :param request: The authorization request
        :param sid:
        :param kwargs:
        :return: A dictionary with 'response_args'
        """

        response_info = {}
        _mngr = self.endpoint_context.session_manager
        user_id, client_id = unpack_session_key(pre_sid)

        # Do the authorization
        try:
            grant = self.endpoint_context.authz(user_id, client_id, request=request)
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
                _mngr.set([user_id, client_id, grant.id], grant)
            except Exception as err:
                return self.error_response(
                    response_info, "server_error", "{}".format(err.args)
                )
            else:
                session_id = session_key(user_id, client_id, grant.id)

        logger.debug("response type: %s" % request["response_type"])

        response_info = self.create_authn_response(request, session_id)

        logger.debug("Known clients: {}".format(list(self.endpoint_context.cdb.keys())))

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
            sid=session_id,
            state=request["state"],
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

        return response_info, session_id

    def setup_client_session(self, user_id: str, request: dict) -> str:
        _mngr = self.endpoint_context.session_manager
        client_id = request['client_id']

        _client_info = self.endpoint_context.cdb[client_id]
        sub_type = _client_info.get("subject_type")
        if sub_type and sub_type == "pairwise":
            sector_identifier_uri = _client_info.get("sector_identifier_uri")
            if sector_identifier_uri is None:
                sector_identifier_uri = host_component(_client_info["redirect_uris"][0])

            client_info = ClientSessionInfo(
                authorization_request=request,
                sub=_mngr.sub_func[sub_type](user_id, salt=_mngr.salt,
                                             sector_identifier=sector_identifier_uri)
            )
        else:
            client_info = ClientSessionInfo(
                authorization_request=request,
                sub=_mngr.sub_func['public'](user_id, salt=_mngr.salt)
            )

        _mngr.set([user_id, client_id], client_info)
        return session_key(user_id, client_id)

    def authz_part2(self, user, request, **kwargs):
        """
        After the authentication this is where you should end up

        :param user:
        :param authn_event: The Authorization Event
        :param request: The Authorization Request
        :param subject_type: The subject_type
        :param acr: The acr
        :param salt: The salt used to produce the sub
        :param sector_id: The sector_id used to produce the sub
        :param kwargs: possible other parameters
        :return: A redirect to the redirect_uri of the client
        """

        pre_sid = self.setup_client_session(user, request)

        try:
            resp_info, session_id = self.post_authentication(user, request, pre_sid, **kwargs)
        except Exception as err:
            return self.error_response({}, "server_error", err)

        if "check_session_iframe" in self.endpoint_context.provider_info:
            ec = self.endpoint_context
            salt = rndstr()
            try:
                authn_event = ec.session_manager.get_authentication_event(session_id)
            except KeyError:
                return self.error_response({}, "server_error", "No such session")
            else:
                if authn_event.is_valid() is False:
                    return self.error_response({}, "server_error", "Authentication has timed out")

            _state = b64e(
                as_bytes(json.dumps({"authn_time": authn_event["authn_time"]}))
            )

            opbs_value = ''
            if hasattr(ec.cookie_dealer, 'create_cookie'):
                session_cookie = ec.cookie_dealer.create_cookie(
                    as_unicode(_state),
                    typ="session",
                    cookie_name=ec.cookie_name["session_management"],
                    same_site="None",
                    http_only=False,
                )

                opbs = session_cookie[ec.cookie_name["session_management"]]
                opbs_value = opbs.value
            else:
                logger.debug(
                    "Failed to set Cookie, that's not configured in main configuration.")

            logger.debug(
                "compute_session_state: client_id=%s, origin=%s, opbs=%s, salt=%s",
                request["client_id"],
                resp_info["return_uri"],
                opbs_value,
                salt,
            )

            _session_state = compute_session_state(
                opbs_value, salt, request["client_id"], resp_info["return_uri"]
            )

            if opbs_value:
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

        :param request_info: The authorization request as a Message instance
        :return: dictionary
        """

        if isinstance(request_info, self.error_cls):
            return request_info

        _cid = request_info["client_id"]
        cinfo = self.endpoint_context.cdb[_cid]
        logger.debug("client {}: {}".format(_cid, cinfo))

        # this apply the default optionally deny_unknown_scopes policy
        if cinfo:
            check_unknown_scopes_policy(request_info, cinfo, self.endpoint_context)

        cookie = kwargs.get("cookie", "")
        if cookie:
            del kwargs["cookie"]

        if proposed_user(request_info):
            kwargs["req_user"] = proposed_user(request_info)
        else:
            if request_info.get("login_hint"):
                _login_hint = request_info["login_hint"]
                if self.endpoint_context.login_hint_lookup:
                    kwargs["req_user"] = self.endpoint_context.login_hint_lookup[
                        _login_hint
                    ]

        info = self.setup_auth(
            request_info, request_info["redirect_uri"], cinfo, cookie, **kwargs
        )

        if "error" in info:
            return info

        _function = info.get("function")
        if not _function:
            logger.debug("- authenticated -")
            logger.debug("AREQ keys: %s" % request_info.keys())
            return self.authz_part2(user=info["user"], request=request_info, cookie=cookie)

        try:
            # Run the authentication function
            return {
                "http_response": _function(**info["args"]),
                "return_uri": request_info["redirect_uri"],
            }
        except Exception as err:
            logger.exception(err)
            return {"http_response": "Internal error: {}".format(err)}
