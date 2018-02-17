import json

from oicmsg import oic

from oicsrv.endpoint import Endpoint


class Discovery(Endpoint):
    request_cls = oic.DiscoveryRequest
    response_cls = oic.JRD
    request_format = 'urlencoded'
    response_format = 'json'

    def do_response(self, srv_info, response_args=None, request=None, **kwargs):
        """
        **Placeholder for the time being**

        :param srv_info: :py:class:`oicsrv.srv_info.SrvInfo` instance
        :param kwargs: request arguments
        :return:
        """

        info = {
            'response': json.dumps({'locations':[srv_info.issuer]}),
            'http_headers': [('Content-type', 'application/json')]
        }

        return info
