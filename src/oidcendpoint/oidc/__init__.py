from oidcendpoint.endpoint_context import EndpointContext


class Client(object):
    def __init__(self, conf):
        self.endpoint_context = EndpointContext(conf)
        self.service = {}

    def respond_to_request(self, endpoint, request, **kwargs):
        _srv = self.service[endpoint]
        _req = _srv.parse_request(request, self.endpoint_context)
        _resp = _srv.process_request(self.endpoint_context, _req)
        _resp = _srv.do_response(self.endpoint_context, _resp)

        # response sending !!!
