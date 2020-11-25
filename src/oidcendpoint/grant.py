import json
import time
from typing import Optional
from uuid import uuid1

from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.time_util import utc_time_sans_frac


class MintingNotAllowed(Exception):
    pass


class GrantMessage(Message):
    c_param = {
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,  # As defined in RFC6749
        "authorization_details": SINGLE_OPTIONAL_JSON,  # As defined in draft-lodderstedt-oauth-rar
        "claims": SINGLE_OPTIONAL_JSON,  # As defined in OIDC core
        "resources": OPTIONAL_LIST_OF_STRINGS,  # As defined in RFC8707
    }


GRANT_TYPE_MAP = {
    "authorization_code": "code",
    "access_token": "access_token",
    "refresh_token": "refresh_token"
}


def find_token(issued, id):
    for iss in issued:
        if iss.id == id:
            return iss
    return None


class Item:
    def __init__(self,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_at: int = 0,
                 not_before: int = 0,
                 revoked: bool = False,
                 used: int = 0
                 ):
        self.issued_at = issued_at or utc_time_sans_frac()
        self.not_before = not_before
        self.expires_at = expires_at
        self.revoked = revoked
        self.used = used
        self.usage_rules = usage_rules or {}

    def max_usage_reached(self):
        if "max_usage" in self.usage_rules:
            return self.used >= self.usage_rules['max_usage']
        else:
            return False

    def is_active(self, now=0):
        if self.max_usage_reached():
            return False

        if self.revoked:
            return False

        if now == 0:
            now = time.time()

        if self.not_before:
            if now < self.not_before:
                return False

        if self.expires_at:
            if now > self.expires_at:
                return False

        return True

    def revoke(self):
        self.revoked = True


class Token(Item):
    attributes = ["type", "issued_at", "not_before", "expires_at", "revoked", "value",
                  "usage_rules", "used", "based_on", "id", "scope", "claims",
                  "resources"]

    def __init__(self,
                 type: str = '',
                 value: str = '',
                 based_on: Optional[str] = None,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_at: int = 0,
                 not_before: int = 0,
                 revoked: bool = False,
                 used: int = 0,
                 id: str = "",
                 scope: Optional[list] = None,
                 claims: Optional[dict] = None,
                 resources: Optional[list] = None,
                 ):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at, expires_at=expires_at,
                      not_before=not_before, revoked=revoked, used=used)

        self.type = type
        self.value = value
        self.based_on = based_on
        self.id = id or uuid1().hex
        self.set_defaults()
        self.scope = scope or []
        self.claims = claims or {}  # default is to not release any user information
        self.resources = resources or []

    def set_defaults(self):
        pass

    def register_usage(self):
        self.used += 1

    def has_been_used(self):
        return self.used != 0

    def to_json(self):
        d = {
            "type": self.type,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "value": self.value,
            "usage_rules": self.usage_rules,
            "used": self.used,
            "based_on": self.based_on,
            "id": self.id,
            "scope": self.scope,
            "claims": self.claims,
            "resources": self.resources
        }
        return json.dumps(d)

    def from_json(self, json_str):
        d = json.loads(json_str)
        for attr in self.attributes:
            if attr in d:
                setattr(self, attr, d[attr])
        return self

    def supports_minting(self, token_type):
        _supports_minting = self.usage_rules.get("supports_minting")
        if _supports_minting is None:
            return False
        else:
            return token_type in _supports_minting


class AccessToken(Token):
    pass


class AuthorizationCode(Token):
    def set_defaults(self):
        if "supports_minting" not in self.usage_rules:
            self.usage_rules['supports_minting'] = ["access_token", "refresh_token"]

        self.usage_rules['max_usage'] = 1


class RefreshToken(Token):
    def set_defaults(self):
        if "supports_minting" not in self.usage_rules:
            self.usage_rules['supports_minting'] = ["access_token", "refresh_token"]


TOKEN_MAP = {
    "authorization_code": AuthorizationCode,
    "access_token": AccessToken,
    "refresh_token": RefreshToken
}


class Grant(Item):
    parameters = ["scope", "claim", "resources", "authorization_details",
                  "issued_token", "usage_rules", "revoked", "issued_at",
                  "expires_at"]

    def __init__(self,
                 scope: Optional[list] = None,
                 claim: Optional[dict] = None,
                 resources: Optional[list] = None,
                 authorization_details: Optional[dict] = None,
                 issued_token: Optional[list] = None,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_at: int = 0,
                 revoked: bool = False,
                 token_map: Optional[dict] = None):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at, expires_at=expires_at,
                      revoked=revoked)
        self.scope = scope or []
        self.authorization_details = authorization_details or None
        self.claims = claim or {}  # default is to not release any user information
        self.resources = resources or []
        self.issued_token = issued_token or []
        self.id = uuid1().hex

        if token_map is None:
            self.token_map = TOKEN_MAP
        else:
            self.token_map = token_map

    def _update_dict(self, attr, val):
        _old = getattr(self, attr)
        if _old:
            _old.update(val)
            setattr(self, attr, _old)
        else:
            setattr(self, attr, val)

    def _update_set(self, attr, val):
        _old = getattr(self, attr)
        if _old:
            _new = list(set(_old).union(set(val)))
            setattr(self, attr, _new)
        else:
            setattr(self, attr, list(set(val)))

    def update(self,
               authorization_details: Optional[dict] = None,
               claims: Optional[dict] = None,
               scope: Optional[list] = None,
               resources: Optional[list] = None):

        if authorization_details:
            self._update_dict("authorization_details", authorization_details)
        if claims:
            self._update_dict("claims", claims)
        if scope:
            self._update_set("scope", scope)
        if resources:
            self._update_set("resources", resources)

    def replace(self, **kwargs):
        for attr in ['scope', 'authorization_details', 'claims', 'resources']:
            new = kwargs.get(attr)
            if new:
                setattr(self, attr, new)

    def get(self):
        return GrantMessage(scope=self.scope, claims=self.claims,
                            authorization_details=self.authorization_details,
                            resources=self.resources)

    def to_json(self):
        d = {
            "type": "grant",
            "scope": self.scope,
            "authorization_details": self.authorization_details,
            "claims": self.claims,
            "resources": self.resources,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "issued_token": [t.to_json() for t in self.issued_token],
            "id": self.id
        }
        return json.dumps(d)

    def from_json(self, json_str):
        d = json.loads(json_str)
        for attr in ["scope", "authorization_details", "claims", "resources",
                     "issued_at", "not_before", "expires_at", "revoked", "id"]:
            if attr in d:
                setattr(self, attr, d[attr])
        if "issued_token" in d:
            _it = []
            for js in d["issued_token"]:
                args = json.loads(js)
                _it.append(TOKEN_MAP[args["type"]](**args))
            setattr(self, "issued_token", _it)

        return self

    def mint_token(self, token_type: str, value: str,
                   based_on: Optional[Token] = None,
                   **kwargs) -> Optional[Token]:
        if self.is_active() is False:
            return None

        if based_on:
            if based_on.supports_minting(token_type) and based_on.is_active():
                _base_on_ref = based_on.value
            else:
                raise MintingNotAllowed()
        else:
            _base_on_ref = None

        if not "usage_rules" in kwargs and token_type in self.usage_rules:
            kwargs["usage_rules"] = self.usage_rules[token_type]

        item = self.token_map[token_type](type=token_type,
                                          value=value,
                                          based_on=_base_on_ref,
                                          **kwargs)
        self.issued_token.append(item)
        self.used += 1
        return item

    def get_token(self, value: str) -> Optional[Token]:
        for t in self.issued_token:
            if t.value == value:
                return t
        return None

    def revoke_token(self,
                     value: Optional[str] = "",
                     based_on: Optional[str] = "",
                     recursive: bool = True):
        for t in self.issued_token:
            if not value and not based_on:
                t.revoked = True
            elif value and based_on:
                if value == t.value and based_on == t.based_on:
                    t.revoked = True
            elif value and t.value == value:
                t.revoked = True
                if recursive:
                    self.revoke_token(based_on=t.value)
            elif based_on and t.based_on == based_on:
                t.revoked = True
                if recursive:
                    self.revoke_token(based_on=t.value)


DEFAULT_USAGE = {
    "authorization_code": {
        "max_usage": 1,
        "supports_minting": ["access_token", "refresh_token", "id_token"],
        "expires_in": 300
    },
    "access_token": {
        "supports_minting": [],
        "expires_in": 3600
    },
    "refresh_token": {
        "supports_minting": ["access_token", "refresh_token", "id_token"]
    }
}


def get_usage_rules(token_type, endpoint_context, grant, client_id):
    """
    The order of importance:
    Grant, Client, EndPointContext, Default

    :param token_type: The type of token
    :param endpoint_context: An EndpointContext instance
    :param grant: A Grant instance
    :param client_id: The client identifier
    :return: Usage specification
    """

    if token_type in endpoint_context.token_usage_rules:
        _usage = endpoint_context.token_usage_rules[token_type]
    else:
        _usage = DEFAULT_USAGE[token_type]

    _cinfo = endpoint_context.cdb.get(client_id, {})
    if "token_usage_rules" in _cinfo:
        _usage.update(_cinfo["token_usage_rules"])

    _grant_usage = grant.usage_rules.get(token_type)
    if _grant_usage:
        _usage.update(_grant_usage)

    return _usage
