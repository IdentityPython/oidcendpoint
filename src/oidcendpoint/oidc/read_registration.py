from oic.oauth2 import ErrorResponse
from oidcmsg.message import Message
from oidcmsg.oidc import RegistrationResponse

from oidcendpoint.endpoint import Endpoint
from oidcendpoint.oidc.registration import comb_uri


class RegistrationRead(Endpoint):
    request_cls = Message
    response_cls = RegistrationResponse
    error_response = ErrorResponse
    request_format = "urlencoded"
    request_placement = "url"
    response_format = "json"
    endpoint_name = ""

    def get_client_id_from_token(self, endpoint_context, token, request=None):
        if "client_id" in request:
            if (
                request["client_id"]
                == self.endpoint_context.registration_access_token[token]
            ):
                return request["client_id"]
        return ""

    def process_request(self, request=None, **kwargs):
        args = dict(
            [
                (k, v)
                for k, v in self.endpoint_context.cdb[request["client_id"]].items()
                if k in RegistrationResponse.c_param
            ]
        )

        comb_uri(args)
        resp = RegistrationResponse(**args)
        return {"response_args": resp}
