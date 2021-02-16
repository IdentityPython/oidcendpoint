import json
from typing import Optional
from uuid import uuid1

from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.oauth2 import AuthorizationRequest

from oidcendpoint.authn_event import AuthnEvent
from oidcendpoint.session import MintingNotAllowed
from oidcendpoint.session import unpack_session_key
from oidcendpoint.session.token import AccessToken
from oidcendpoint.session.token import AuthorizationCode
from oidcendpoint.session.token import Item
from oidcendpoint.session.token import RefreshToken
from oidcendpoint.session.token import Token
from oidcendpoint.token import Token as TToken
from oidcendpoint.util import importer


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


TOKEN_MAP = {
    "authorization_code": AuthorizationCode,
    "access_token": AccessToken,
    "refresh_token": RefreshToken
}


class Grant(Item):
    attributes = ["scope", "claim", "resources", "authorization_details",
                  "issued_token", "usage_rules", "revoked", "issued_at",
                  "expires_at", "sub", "authorization_request",
                  "authentication_event"]
    type = "grant"

    def __init__(self,
                 scope: Optional[list] = None,
                 claims: Optional[dict] = None,
                 resources: Optional[list] = None,
                 authorization_details: Optional[dict] = None,
                 authorization_request: Optional[Message] = None,
                 authentication_event: Optional[AuthnEvent] = None,
                 issued_token: Optional[list] = None,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_in: int = 0,
                 expires_at: int = 0,
                 revoked: bool = False,
                 token_map: Optional[dict] = None,
                 sub: Optional[str] = ""):
        Item.__init__(self, usage_rules=usage_rules, issued_at=issued_at,
                      expires_in=expires_in, expires_at=expires_at, revoked=revoked)
        self.scope = scope or []
        self.authorization_details = authorization_details or None
        self.authorization_request = authorization_request or None
        self.authentication_event = authentication_event or None
        self.claims = claims or {}  # default is to not release any user information
        self.resources = resources or []
        self.issued_token = issued_token or []
        self.id = uuid1().hex
        self.sub = sub

        if token_map is None:
            self.token_map = TOKEN_MAP
        else:
            self.token_map = token_map

    def get(self) -> object:
        return GrantMessage(scope=self.scope, claims=self.claims,
                            authorization_details=self.authorization_details,
                            resources=self.resources)

    def to_json(self) -> str:
        d = {
            "type": self.type,
            "scope": self.scope,
            "sub": self.sub,
            "authorization_details": self.authorization_details,
            "claims": self.claims,
            "resources": self.resources,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "issued_token": [t.to_json() for t in self.issued_token],
            "id": self.id,
            "token_map": {k: ".".join([v.__module__, v.__name__]) for k, v in
                          self.token_map.items()}
        }

        if self.authorization_request:
            if isinstance(self.authorization_request, Message):
                d["authorization_request"] = self.authorization_request.to_dict()
            elif isinstance(self.authorization_request, dict):
                d["authorization_request"] = self.authorization_request

        if self.authentication_event:
            if isinstance(self.authentication_event, Message):
                d["authentication_event"] = self.authentication_event.to_dict()
            elif isinstance(self.authentication_event, dict):
                d["authentication_event"] = self.authentication_event

        return json.dumps(d)

    def from_json(self, json_str: str) -> 'Grant':
        d = json.loads(json_str)
        for attr in ["scope", "authorization_details", "claims", "resources", "sub",
                     "issued_at", "not_before", "expires_at", "revoked", "id"]:
            if attr in d:
                setattr(self, attr, d[attr])

        if "authentication_event" in d:
            self.authentication_event = AuthnEvent(**d["authentication_event"])
        if "authorization_request" in d:
            self.authorization_request = AuthorizationRequest(**d["authorization_request"])

        if "token_map" in d:
            self.token_map = {k: importer(v) for k, v in d["token_map"].items()}
        else:
            self.token_map = TOKEN_MAP

        if "issued_token" in d:
            _it = []
            for js in d["issued_token"]:
                args = json.loads(js)
                _it.append(self.token_map[args["type"]](**args))
            setattr(self, "issued_token", _it)

        return self

    def payload_arguments(self, session_id: str, endpoint_context,
                          token_type: str, scope: Optional[dict] = None) -> dict:
        """

        :return: dictionary containing information to place in a token value
        """
        if not scope:
            scope = self.scope

        payload = {
            "scope": scope,
            "aud": self.resources
        }

        _claims_restriction = endpoint_context.claims_interface.get_claims(session_id,
                                                                           scopes=scope,
                                                                           usage=token_type)
        user_id, _, _ = unpack_session_key(session_id)
        user_info = endpoint_context.claims_interface.get_user_claims(user_id,
                                                                      _claims_restriction)
        payload.update(user_info)

        return payload

    def mint_token(self,
                   session_id: str,
                   endpoint_context: object,
                   token_type: str,
                   token_handler: TToken,
                   based_on: Optional[Token] = None,
                   usage_rules: Optional[dict] = None,
                   scope: Optional[list] = None,
                   **kwargs) -> Optional[Token]:
        """

        :param session_id:
        :param endpoint_context:
        :param token_type:
        :param token_handler:
        :param based_on:
        :param usage_rules:
        :param scope:
        :param kwargs:
        :return:
        """
        if self.is_active() is False:
            return None

        if based_on:
            if based_on.supports_minting(token_type) and based_on.is_active():
                _base_on_ref = based_on.value
            else:
                raise MintingNotAllowed()
        else:
            _base_on_ref = None

        if usage_rules is None and token_type in self.usage_rules:
            usage_rules = self.usage_rules[token_type]

        token_class = self.token_map.get(token_type)
        if token_class:
            item = token_class(type=token_type,
                               based_on=_base_on_ref,
                               usage_rules=usage_rules,
                               scope=scope,
                               **kwargs)
            if token_handler is None:
                token_handler = endpoint_context.session_manager.token_handler.handler[
                    GRANT_TYPE_MAP[token_type]]

            item.value = token_handler(session_id=session_id,
                                       **self.payload_arguments(session_id,
                                                                endpoint_context,
                                                                token_type=token_type,
                                                                scope=scope))
        else:
            raise ValueError("Can not mint that kind of token")

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

    def get_spec(self, token: Token) -> Optional[dict]:
        if self.is_active() is False or token.is_active is False:
            return None

        res = {}
        for attr in ["scope", "claims", "resources"]:
            _val = getattr(token, attr)
            if _val:
                res[attr] = _val
            else:
                _val = getattr(self, attr)
                if _val:
                    res[attr] = _val
        return res


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

    _usage = endpoint_context.authz.usage_rules_for(token_type)
    if not _usage:
        _usage = DEFAULT_USAGE[token_type]

    _cinfo = endpoint_context.cdb.get(client_id, {})
    if "token_usage_rules" in _cinfo:
        try:
            _usage.update(_cinfo["token_usage_rules"][token_type])
        except KeyError:
            pass

    _grant_usage = grant.usage_rules.get(token_type)
    if _grant_usage:
        _usage.update(_grant_usage)

    return _usage


class ExchangeGrant(Grant):
    attributes = Grant.attributes
    attributes.append("users")
    type = "exchange_grant"

    def __init__(self,
                 scope: Optional[list] = None,
                 claims: Optional[dict] = None,
                 resources: Optional[list] = None,
                 authorization_details: Optional[dict] = None,
                 issued_token: Optional[list] = None,
                 usage_rules: Optional[dict] = None,
                 issued_at: int = 0,
                 expires_in: int = 0,
                 expires_at: int = 0,
                 revoked: bool = False,
                 token_map: Optional[dict] = None,
                 users: list = None):
        Grant.__init__(self, scope=scope, claims=claims, resources=resources,
                       authorization_details=authorization_details,
                       issued_token=issued_token, usage_rules=usage_rules,
                       issued_at=issued_at, expires_in=expires_in,
                       expires_at=expires_at, revoked=revoked,
                       token_map=token_map)

        self.users = users or []
        self.usage_rules = {
            "access_token": {
                "supports_minting": ["access_token"],
                "expires_in": 60
            }
        }
