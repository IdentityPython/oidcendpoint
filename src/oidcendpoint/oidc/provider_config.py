import logging

from oidcmsg import oidc

from oidcendpoint.endpoint import Endpoint

logger = logging.getLogger(__name__)


class ProviderConfiguration(Endpoint):
    request_cls = oidc.Message
    response_cls = oidc.ProviderConfigurationResponse
    request_format = ''
    response_format = 'json'
    #response_placement = 'body'

    def process_request(self, srv_info, request=None, **kwargs):
        return {'response_args': srv_info.provider_info}

