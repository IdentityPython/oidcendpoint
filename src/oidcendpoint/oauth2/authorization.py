import logging

from oidcmsg import oauth2

from oidcendpoint.common import authorization
from oidcendpoint.common.authorization import check_unknown_scopes_policy
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.session_management import ClientSessionInfo
from oidcendpoint.session_management import session_key

logger = logging.getLogger(__name__)


# def re_authenticate(request, authn):
#     return False


class Authorization(authorization.Authorization):
    request_cls = oauth2.AuthorizationRequest
    response_cls = oauth2.AuthorizationResponse
    error_cls = oauth2.AuthorizationErrorResponse
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
        "scopes_supported": [],
    }

    def __init__(self, endpoint_context, **kwargs):
        authorization.Authorization.__init__(self, endpoint_context, **kwargs)
        # self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._do_request_uri)
        self.post_parse_request.append(self._post_parse_request)
        # Has to be done elsewhere. To make sure things happen in order.
        # self.scopes_supported = available_scopes(endpoint_context)

    def setup_client_session(self, user_id: str, request: dict) -> str:
        _mngr = self.endpoint_context.session_manager
        client_id = request['client_id']

        client_info = ClientSessionInfo(
            authorization_request=request,
            sub=_mngr.sub_func['public'](user_id, salt=_mngr.salt)
        )

        _mngr.set([user_id, client_id], client_info)
        return session_key(user_id, client_id)
