from oidcendpoint.endpoint_context import EndpointContext


class Client(object):
    def __init__(self, conf):
        self.srv_info = EndpointContext(conf)
        self.service = {}

    def respond_to_request(self, endpoint, request, **kwargs):
        _srv = self.service[endpoint]
        _req = _srv.parse_request(request, self.srv_info)
        _resp = _srv.process_request(self.srv_info, _req)
        _resp = _srv.do_response(self.srv_info, _resp)

        # response sending !!!
