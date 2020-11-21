import json
import logging
from urllib.parse import urlsplit

from cryptojwt import BadSyntax
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64d
from cryptojwt.utils import b64e
from oidcmsg import oidc
from oidcmsg.exception import ParameterError
from oidcmsg.oidc import Claims
from oidcmsg.oidc import verified_claim_name

from oidcendpoint import rndstr
from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.common import authorization
from oidcendpoint.common.authorization import FORM_POST
from oidcendpoint.common.authorization import AllowedAlgorithms
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
from oidcendpoint.exception import TamperAllert
from oidcendpoint.exception import ToOld
from oidcendpoint.oauth2.authorization import check_unknown_scopes_policy
from oidcendpoint.session_management import ClientSessionInfo
from oidcendpoint.session_management import UserSessionInfo
from oidcendpoint.session_management import session_key
from oidcendpoint.session_management import unpack_session_key
from oidcendpoint.token_handler import UnknownToken

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


class Authorization(authorization.Authorization):
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
        authorization.Authorization.__init__(self, endpoint_context, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._do_request_uri)
        self.post_parse_request.append(self._post_parse_request)

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
            sub_type = self.kwargs.get("subject_type")
            if not sub_type:
                sub_type = "public"

            client_info = ClientSessionInfo(
                authorization_request=request,
                sub=_mngr.sub_func[sub_type](user_id, salt=_mngr.salt)
            )

        _mngr.set([user_id, client_id], client_info)
        return session_key(user_id, client_id)

    def do_request_user(self, request_info, **kwargs):
        if proposed_user(request_info):
            kwargs["req_user"] = proposed_user(request_info)
        else:
            if request_info.get("login_hint"):
                _login_hint = request_info["login_hint"]
                if self.endpoint_context.login_hint_lookup:
                    kwargs["req_user"] = self.endpoint_context.login_hint_lookup[
                        _login_hint
                    ]
        return kwargs

