import logging

from oidcendpoint.user_info import SCOPE2CLAIMS

LOGGER = logging.getLogger(__name__)


def add_custom_scopes(endpoint, **kwargs):
    """
    :param endpoint: A dictionary with endpoint instances as values
    """
    # Just need an endpoint, anyone will do
    _endpoint = list(endpoint.values())[0]

    _scopes = SCOPE2CLAIMS.copy()
    _scopes.update(kwargs)

    _endpoint.scope_to_claims = _scopes
    _endpoint.endpoint_context.idtoken.scope_to_claims = _scopes
    _endpoint.endpoint_context.scope2claims = _scopes
