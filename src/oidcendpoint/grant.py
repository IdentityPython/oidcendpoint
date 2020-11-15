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


class Token(Item):
    attributes = ["type", "issued_at", "not_before", "expires_at", "revoked", "value",
                  "usage_rules", "used", "based_on", "id"]

    def __init__(self,
                 type: str = '',
                 based_on: Optional[str] = None,
                 usage_rules: Optional[dict] = None,
                 value: Optional[str] = '',
                 issued_at: int = 0,
                 expires_at: int = 0,
                 not_before: int = 0,
                 revoked: bool = False,
                 used: int = 0,
                 id: str = ""
                 ):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at, expires_at=expires_at,
                      not_before=not_before, revoked=revoked, used=used)

        self.type = type
        self.value = value
        self.based_on = based_on
        self.id = id or uuid1().hex
        self.set_defaults()

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
            "id": self.id
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
    def __init__(self,
                 scope: Optional[list] = None,
                 claim: Optional[dict] = None,
                 resources: Optional[list] = None,
                 authorization_details: Optional[dict] = None,
                 token: Optional[list] = None,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_at: int = 0,
                 revoked: bool = False):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at, expires_at=expires_at)
        self.scope = scope or []
        self.authorization_details = authorization_details or None
        self.claims = claim or {}  # default is to not release any user information
        self.resources = resources or []
        self.issued_token = token or []
        self.id = uuid1().hex

    def update(self, item: dict):
        for attr in ['scope', 'authorization_details', 'claims', 'resources']:
            val = item.get(attr)
            if val:
                setattr(self, attr, val)

    def replace(self, item: dict):
        for attr in ['scope', 'authorization_details', 'claims', 'resources']:
            setattr(self, attr, item.get(attr))

    def revoke_all(self):
        self.revoked = True
        for t in self.issued_token:
            t.revoked = True

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
        for attr in ["scope", "authorization_details", "claims", "resources", "issued_at",
                     "not_before", "expires_at", "revoked", "id"]:
            if attr in d:
                setattr(self, attr, d[attr])
        if "issued_token" in d:
            _it = []
            for js in d["issued_token"]:
                args = json.loads(js)
                _it.append(TOKEN_MAP[args["type"]](**args))
            setattr(self, "issued_token", _it)

        return self

    def mint_token(self, token_type: str, based_on: Optional[Token] = None, **kwargs) -> Token:
        if based_on:
            if based_on.supports_minting(token_type) and based_on.is_active():
                _base_on_ref = based_on.value
            else:
                raise MintingNotAllowed()
        else:
            _base_on_ref = None

        if not "usage_rules" in kwargs and token_type in self.usage_rules:
            kwargs["usage_rules"] = self.usage_rules[token_type]

        item = TOKEN_MAP[token_type](type=token_type, based_on=_base_on_ref, **kwargs)
        self.issued_token.append(item)

        return item

    def revoke_all_based_on(self, id):
        for t in self.issued_token:
            if t.based_on == id:
                t.revoked = True
                self.revoke_all_based_on(t.id)

    def get_token(self, val):
        for t in self.issued_token:
            if t.value == val:
                return t
        return None

    def revoke_token(self, val):
        for t in self.issued_token:
            if t.value == val:
                t.revoked = True


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
