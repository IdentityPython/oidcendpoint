import inspect
import logging
import sys

from oidcendpoint import sanitize
from oidcendpoint.cookie import cookie_value

logger = logging.getLogger(__name__)


class AuthzHandling(object):
    """ Class that allow an entity to manage authorization """

    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.cookie_dealer = endpoint_context.cookie_dealer
        self.permdb = {}
        self.kwargs = kwargs

    def __call__(self, *args, **kwargs):
        return ""

    def set(self, uid, client_id, permission):
        try:
            self.permdb[uid][client_id] = permission
        except KeyError:
            self.permdb[uid] = {client_id: permission}

    def permissions(self, cookie=None, **kwargs):
        if cookie is None:
            return None
        else:
            logger.debug("kwargs: %s" % sanitize(kwargs))

            val = self.cookie_dealer.get_cookie_value(cookie)
            if val is None:
                return None
            else:
                b64, _ts, typ = val

            info = cookie_value(b64)
            return self.get(info["sub"], info["client_id"])

    def get(self, uid, client_id):
        try:
            return self.permdb[uid][client_id]
        except KeyError:
            return None


class Implicit(AuthzHandling):
    def __init__(self, endpoint_context, permission="implicit"):
        AuthzHandling.__init__(self, endpoint_context)
        self.permission = permission

    def permissions(self, cookie=None, **kwargs):
        return self.permission

    def get(self, uid, client_id):
        return self.permission


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
