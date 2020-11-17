import json

from oidcendpoint.grant import Grant
from oidcendpoint.session_management import ClientSessionInfo
from oidcendpoint.session_management import UserSessionInfo


class JSON:
    def serialize(self, instance):
        return instance.to_json()

    def deserialize(self, js):
        args = json.loads(js)
        if args["type"] == "UserSessionInfo":
            return UserSessionInfo().from_json(js)
        elif args["type"] == "ClientSessionInfo":
            return ClientSessionInfo().from_json(js)
        elif args["type"] == "grant":
            return Grant().from_json(js)
