import inspect
import logging
import sys

from oidcendpoint.grant import Grant

logger = logging.getLogger(__name__)


class AuthzHandling(object):
    """ Class that allow an entity to manage authorization """

    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.cookie_dealer = endpoint_context.cookie_dealer
        self.kwargs = kwargs

    def __call__(self, user_id, client_id, request):
        args = {}
        scope = request.get("scope")
        if scope:
            args["scope"] = scope
        claims = request.get("claims")
        if claims:
            args["claim"] = claims.to_dict()
        return Grant(**args)


class Implicit(AuthzHandling):
    def __init__(self, endpoint_context):
        AuthzHandling.__init__(self, endpoint_context)

    def __call__(self, user_id, client_id, request):
        return Grant()


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
