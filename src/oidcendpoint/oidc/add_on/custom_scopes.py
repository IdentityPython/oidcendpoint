import logging

from oidcendpoint.user_info import SCOPE2CLAIMS

LOGGER = logging.getLogger(__name__)


def add_custom_scopes(endpoint, **kwargs):
    userinfo_endpoint = endpoint['userinfo']

    _scopes = SCOPE2CLAIMS.copy()
    _scopes.update(kwargs)

    userinfo_endpoint.scope_to_claims = _scopes
    userinfo_endpoint.endpoint_context.idtoken.scope_to_claims = _scopes
    userinfo_endpoint.endpoint_context.scope2claims = _scopes
