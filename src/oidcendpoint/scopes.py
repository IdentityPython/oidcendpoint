# default set can be changed by configuration
from oidcmsg.oidc import OpenIDSchema

SCOPE2CLAIMS = {
    "openid": ["sub"],
    "profile": [
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
        "preferred_username",
    ],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number", "phone_number_verified"],
    "offline_access": [],
}

IGNORE = ["error", "error_description", "error_uri", "_claim_names", "_claim_sources"]
STANDARD_CLAIMS = [c for c in OpenIDSchema.c_param.keys() if c not in IGNORE]


def available_scopes(endpoint_context):
    _supported = endpoint_context.provider_info.get("scopes_supported")
    if _supported:
        return [s for s in endpoint_context.scope2claims.keys() if s in _supported]
    else:
        return [s for s in endpoint_context.scope2claims.keys()]


def available_claims(endpoint_context):
    _supported = endpoint_context.provider_info.get("claims_supported")
    if _supported:
        return _supported
    else:
        return STANDARD_CLAIMS


def convert_scopes2claims(scopes, allowed_claims, map=None):
    if map is None:
        map = SCOPE2CLAIMS

    res = {}
    for scope in scopes:
        try:
            claims = dict(
                [(name, None) for name in map[scope] if name in allowed_claims]
            )
            res.update(claims)
        except KeyError:
            continue
    return res


class Scopes:
    def __init__(self):
        pass

    def allowed_scopes(self, client_id, endpoint_context):
        """
        Returns the set of scopes that a specific client can use.

        :param client_id: The client identifier
        :param endpoint_context: A EndpointContext instance
        :returns: List of scope names. Can be empty.
        """
        _cli = endpoint_context.cdb.get(client_id)
        if _cli is not None:
            _scopes = _cli.get("allowed_scopes")
            if _scopes:
                return _scopes
            else:
                return available_scopes(endpoint_context)
        return []


class Claims:
    def __init__(self):
        pass

    def allowed_claims(self, client_id, endpoint_context):
        """
        Returns the set of claims that a specific client can use.

        :param client_id: The client identifier
        :param endpoint_context: A EndpointContext instance
        :returns: List of claim names. Can be empty.
        """
        _cli = endpoint_context.cdb.get(client_id)
        if _cli is not None:
            _claims = _cli.get("allowed_claims")
            if _claims:
                return _claims
            else:
                return available_claims(endpoint_context)
        return []
