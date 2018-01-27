from oicmsg import oic

from oicsrv.endpoint import Endpoint


class Discovery(Endpoint):
    request_cls = oic.DiscoveryRequest
    response_cls = oic.DiscoveryResponse
    request_format = 'urlencoded'
    response_format = 'json'
    #response_placement = 'body'

    def process_request(self, srv_info, **kwargs):
        return {'location': srv_info.issuer}


