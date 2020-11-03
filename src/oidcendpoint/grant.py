import json
import time
from typing import Optional
from uuid import uuid1

from oidcmsg.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import Message
from oidcmsg.time_util import utc_time_sans_frac


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
                 not_before: int = 0
                 ):
        self.issued_at = issued_at or utc_time_sans_frac()
        self.not_before = not_before
        self.expires_at = expires_at
        self.revoked = False
        self.used = 0
        self.usage_rules = usage_rules or {}

    def max_usage_reached(self):
        if "max_usage" in self.usage_rules:
            return self.used >= self.usage_rules['max_usage']
        else:
            return False

    def is_active(self):
        if self.max_usage_reached():
            return False

        if self.revoked:
            return False

        if self.not_before:
            if time.time() < self.not_before:
                return False

        if self.expires_at:
            if time.time() > self.expires_at:
                return False

        return True


class Token(Item):
    attributes = ["type", "issued_at", "not_before", "expires_at", "revoked", "value",
                  "usage_rules", "used", "based_on", "id"]

    def __init__(self,
                 typ: str = '',
                 based_on: Optional[str] = None,
                 usage_rules: Optional[dict] = None,
                 value: Optional[str] = '',
                 issued_at: int = 0,
                 expires_at: int = 0,
                 not_before: int = 0
                 ):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at, expires_at=expires_at,
                      not_before=not_before)

        self.type = typ
        self.value = value
        self.based_on = based_on
        self.id = uuid1().hex

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
        return token_type in self.usage_rules['supports_minting']


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
    "access_token": Token,
    "refresh_token": RefreshToken
}


class Grant(Item):
    def __init__(self,
                 scopes: Optional[list] = None,
                 claims: Optional[dict] = None,
                 resources: Optional[list] = None,
                 authorization_details: Optional[dict] = None,
                 token: Optional[list] = None,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_at: int = 0):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at, expires_at=expires_at)
        self.scope = scopes or []
        self.authorization_details = authorization_details or None
        self.claims = claims or None
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

    def revoke(self):
        self.revoked = True
        for t in self.issued_token:
            t.revoked = True

    def get(self):
        return GrantMessage(scope=self.scope, claims=self.claims,
                            authorization_details=self.authorization_details,
                            resources=self.resources)

    def to_json(self):
        d = {
            "scope": self.scope,
            "authorization_details": self.authorization_details,
            "claims": self.claims,
            "resources": self.resources,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "issued_token": [t.to_json for t in self.issued_token],
            "id": self.id
        }
        return json.dumps(d)

    def from_json(self, json_str):
        d = json.loads(json_str)
        for attr in ["scope", "authorization_details", "claims", "resources", "issued_at",
                     "not_before",
                     "expires_at", "revoked", "id"]:
            if attr in d:
                setattr(self, attr, d[attr])
        if "issued_token" in d:
            setattr(self, "issued_token", [Token(**t) for t in d['issued_token']])

    def mint_token(self, token_type, **kwargs):
        item = TOKEN_MAP[token_type](typ=token_type, **kwargs)
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
