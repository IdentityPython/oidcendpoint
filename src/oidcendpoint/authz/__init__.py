import inspect
import logging
import sys
from typing import Optional
from typing import Union

from oidcmsg.message import Message

from oidcendpoint.grant import Grant

logger = logging.getLogger(__name__)


class AuthzHandling(object):
    """ Class that allow an entity to manage authorization """

    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.cookie_dealer = endpoint_context.cookie_dealer
        self.kwargs = kwargs
        self.grant_config = kwargs.get("grant_config", {})

    def __call__(self, user_id: str, client_id: str, request: Union[dict, Message],
                 resources: Optional[list] = None) -> Grant:
        args = self.grant_config.copy()

        scope = request.get("scope")
        if scope:
            args["scope"] = scope

        claims = request.get("claims")
        if claims:
            args["claims"] = claims.to_dict()

        if resources is None:
            args["resources"] = [client_id]
        else:
            args["resources"] = resources

        grant = Grant(**args)
        # This is where user consent should be handled
        for interface in ["userinfo", "introspection", "id_token", "token"]:
            grant.claims[interface] = self.endpoint_context.claims_interface.get_claims(
                client_id=client_id, user_id=user_id, scopes=request["scope"], usage=interface
            )
        return grant


class Implicit(AuthzHandling):
    def __init__(self, endpoint_context, **kwargs):
        AuthzHandling.__init__(self, endpoint_context, **kwargs)

    def __call__(self, user_id: str, client_id: str, request: Union[dict, Message],
                 resources: Optional[list] = None) -> Grant:
        args = self.grant_config.copy()
        return Grant(**args)


def factory(msgtype, endpoint_context, **kwargs):
    """
    Factory method that can be used to easily instantiate a class instance

    :param msgtype: The name of the class
    :param kwargs: Keyword arguments
    :return: An instance of the class or None if the name doesn't match any
        known class.
    """
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, AuthzHandling):
            try:
                if obj.__name__ == msgtype:
                    return obj(endpoint_context, **kwargs)
            except AttributeError:
                pass
