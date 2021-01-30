import json
from typing import Optional
from uuid import uuid1

from oidcmsg.time_util import time_sans_frac


class MintingNotAllowed(Exception):
    pass


class Item:
    def __init__(self,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_in: int = 0,
                 expires_at: int = 0,
                 not_before: int = 0,
                 revoked: bool = False,
                 used: int = 0
                 ):
        self.issued_at = issued_at or time_sans_frac()
        self.not_before = not_before
        if expires_at == 0 and expires_in != 0:
            self.set_expires_at(expires_in)
        else:
            self.expires_at = expires_at

        self.revoked = revoked
        self.used = used
        self.usage_rules = usage_rules or {}

    def set_expires_at(self, expires_in):
        self.expires_at = time_sans_frac() + expires_in

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
            now = time_sans_frac()

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
                 expires_in: int = 0,
                 expires_at: int = 0,
                 not_before: int = 0,
                 revoked: bool = False,
                 used: int = 0,
                 id: str = "",
                 scope: Optional[list] = None,
                 claims: Optional[dict] = None,
                 resources: Optional[list] = None,
                 ):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at, expires_in=expires_in,
                      expires_at=expires_at, not_before=not_before, revoked=revoked, used=used)

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
