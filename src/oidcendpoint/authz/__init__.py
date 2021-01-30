import inspect
import logging
import sys
from typing import Optional
from typing import Union

from oidcmsg.message import Message

from oidcendpoint.session.grant import Grant

logger = logging.getLogger(__name__)


class AuthzHandling(object):
    """ Class that allow an entity to manage authorization """

    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.cookie_dealer = endpoint_context.cookie_dealer
        self.kwargs = kwargs
        self.grant_config = kwargs.get("grant_config", {})

    def __call__(self, session_id: str, request: Union[dict, Message],
                 resources: Optional[list] = None) -> Grant:
        args = self.grant_config.copy()

        scope = request.get("scope")
        if scope:
            args["scope"] = scope

        claims = request.get("claims")
        if claims:
            args["claims"] = claims.to_dict()

        session_info = self.endpoint_context.session_manager.get_session_info(
            session_id=session_id, grant=True
        )
        grant = session_info["grant"]

        for key, val in args.items():
            if key == "expires_in":
                grant.set_expires_at(val)
            else:
                setattr(grant, key, val)

        if resources is None:
            grant.resources = [session_info["client_id"]]
        else:
            grant.resources = resources

        # This is where user consent should be handled
        for interface in ["userinfo", "introspection", "id_token", "token"]:
            grant.claims[interface] = self.endpoint_context.claims_interface.get_claims(
                session_id=session_id, scopes=request["scope"], usage=interface
            )
        return grant


class Implicit(AuthzHandling):
    def __call__(self, session_id: str, request: Union[dict, Message],
                 resources: Optional[list] = None) -> Grant:
        args = self.grant_config.copy()
        grant = self.endpoint_context.session_manager.get_grant(session_id=session_id)
        for arg, val in args:
            setattr(grant, arg, val)
        return grant


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
