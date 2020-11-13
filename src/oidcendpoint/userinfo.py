import logging

from oidcendpoint.scopes import convert_scopes2claims

logger = logging.getLogger(__name__)


class ClaimsInterface:
    init_args = {
        "add_claims_by_scope": False,
        "enable_claims_per_client": False
    }

    def __init__(self, endpoint_context):
        self.endpoint_context = endpoint_context

    def request_claims(self, user_id, client_id, usage=""):
        if usage in ["id_token", "userinfo"]:
            _csi = self.endpoint_context.session_manager.get([user_id, client_id])
            if "claims" in _csi["authorization_request"]:
                return _csi["authorization_request"]["claims"].get(usage, {})

        return {}

    def _get_client_claims(self, client_id, usage):
        client_info = self.endpoint_context.cdb.get(client_id, {})
        return client_info.get("{}_claims".format(usage), {})

    def get_claims(self, client_id, user_id, scopes, usage):
        """

        :param client_id:
        :param user_id:
        :param scopes:
        :return:
        """

        # base_claims from module
        module = None
        if usage == "userinfo":
            if "userinfo" in self.endpoint_context.endpoint:
                module = self.endpoint_context.endpoint["userinfo"]
        elif usage == "id_token":
            if self.endpoint_context.idtoken:
                module = self.endpoint_context.idtoken
        elif usage == "introspection":
            if "introspection" in self.endpoint_context.endpoint:
                module = self.endpoint_context.endpoint["introspection"]

        if module:
            base_claims = module.kwargs.get("base_claims", {})
        else:
            base_claims = {}

        if module and module.kwargs.get("enable_claims_per_client"):
            claims = self._get_client_claims(client_id, usage)
        else:
            claims = {}

        claims.update(base_claims)

        if module and module.kwargs.get("add_claims_by_scope"):
            _supported = self.endpoint_context.provider_info.get("scopes_supported", [])
            if _supported:
                _scopes = set(_supported).intersection(set(scopes))
            else:
                _scopes = scopes

            _claims = convert_scopes2claims(_scopes, map=self.endpoint_context.scope2claims)
            claims.update(_claims)

        request_claims = self.request_claims(user_id=user_id, client_id=client_id, usage=usage)
        # If they want less then what's possible that's OK.
        if request_claims:
            claims = {k: v for k, v in claims.items() if k in request_claims}

        return claims

    def get_user_claims(self, user_id, claims_restriction):
        """

        :param user_id: User identifier
        :param claims_restriction: Specifies the upper limit of what claims can be returned
        :return:
        """
        if claims_restriction:
            user_info = self.endpoint_context.userinfo(user_id, client_id=None)
            return {k: user_info.get(k) for k, v in claims_restriction.items() if
                    claims_match(user_info.get(k), v)}
        else:
            return {}


def claims_match(value, claimspec):
    """
    Implements matching according to section 5.5.1 of
    http://openid.net/specs/openid-connect-core-1_0.html
    The lack of value is not checked here.
    Also the text doesn't prohibit having both 'value' and 'values'.

    :param value: single value
    :param claimspec: None or dictionary with 'essential', 'value' or 'values'
        as key
    :return: Boolean
    """
    if value is None:
        return False

    if claimspec is None:  # match anything
        return True

    matched = False
    for key, val in claimspec.items():
        if key == "value":
            if value == val:
                matched = True
        elif key == "values":
            if value in val:
                matched = True
        elif key == "essential":
            # Whether it's essential or not doesn't change anything here
            continue

        if matched:
            break

    if matched is False:
        if list(claimspec.keys()) == ["essential"]:
            return True

    return matched


def by_schema(cls, **kwa):
    """
    Will return only those claims that are listed in the Class definition.

    :param cls: A subclass of :py:class:´oidcmsg.message.Message`
    :param kwa: Keyword arguments
    :return: A dictionary with claims (keys) that meets the filter criteria
    """
    return dict([(key, val) for key, val in kwa.items() if key in cls.c_param])
