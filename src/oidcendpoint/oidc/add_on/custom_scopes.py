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

    # add to defaults
    authz_enp = endpoint.get("authorization")
    if authz_enp:
        _supported = set(authz_enp.default_capabilities['scopes_supported'])
        _supported.update(set(kwargs.keys()))
        authz_enp.default_capabilities['scopes_supported'] = list(_supported)

        _claims = set(authz_enp.default_capabilities['claims_supported'])
        for vals in kwargs.values():
            _claims.update(set(vals))
        authz_enp.default_capabilities['claims_supported'] = list(_claims)
