# default set can be changed by configuration
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


def available_scopes(endpoint_context):
    _supported = endpoint_context.provider_info.get("scopes_supported")
    if _supported:
        return [s for s in endpoint_context.scope2claims.keys() if s in _supported]
    else:
        return [s for s in endpoint_context.scope2claims.keys()]


def available_claims(endpoint_context):
    _scopes = available_scopes(endpoint_context)
    _claims = set()
    for _scope in _scopes:
        _claims.update(set(endpoint_context.scope2claims[_scope]))
    _supported = endpoint_context.provider_info.get("claims_supported")
    if _supported:
        return [c for c in _claims if c in _supported]
    else:
        return list(_claims)


def convert_scopes2claims(scopes, map=None):
    if map is None:
        map = SCOPE2CLAIMS

    res = {}
    for scope in scopes:
        try:
            claims = dict([(name, None) for name in map[scope]])
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
        :returns: List of claim names. Can be empty.
        """
        _cli = endpoint_context.cdb.get(client_id)
        if _cli is not None:
            _scopes = _cli.get("allowed_scopes")
            if _scopes:
                return _scopes
            else:
                return available_scopes(endpoint_context)
        return []
