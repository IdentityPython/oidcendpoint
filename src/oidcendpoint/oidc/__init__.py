from oidcendpoint.srv_info import SrvInfo


class Client(object):
    def __init__(self, conf):
        self.srv_info = SrvInfo(conf)
        self.service = {}

    def respond_to_request(self, endpoint, request, **kwargs):
        _srv = self.service[endpoint]
        _req = _srv.parse_request(request, self.srv_info)
        _resp = _srv.process_request(self.srv_info, _req)
        _resp = _srv.do_response(self.srv_info, _resp)

        # response sending !!!
