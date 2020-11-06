from typing import Optional

from cryptojwt import JWT
from cryptojwt.jws.exception import JWSException

from oidcendpoint.exception import ToOld
from oidcendpoint.scopes import convert_scopes2claims
from oidcendpoint.token_handler import is_expired
from oidcendpoint.token_handler import Token
from oidcendpoint.token_handler import UnknownToken


class ClaimsInterface:
    init_args = {
        "add_claims_by_scope": False,
        "enable_claims_per_client": False
    }

    def __init__(self, endpoint_context, **kwargs):
        self.endpoint_context = endpoint_context
        self.scope_claims_map = kwargs.get("scope_claims_map", endpoint_context.scope2claims)
        self.add_claims_by_scope = kwargs.get("add_claims_by_scope",
                                              self.init_args["add_claims_by_scope"])
        self.enable_claims_per_client = kwargs.get("enable_claims_per_client",
                                                   self.init_args["enable_claims_per_client"])

    def _get_client_claims(self, client_id):
        if self.enable_claims_per_client:
            client_info = self.endpoint_context.cdb.get(client_id, {})
            return client_info.get("introspection_claims")
        else:
            return []

    def _get_user_info(self, token_info):
        user_id = self.endpoint_context.sdb.sso_db.get_uid_by_sid(token_info["sid"])
        return self.endpoint_context.userinfo(user_id, client_id=None)

    def add_claims(self, client_id, user_id, payload, scopes, claims_restriction):
        if claims_restriction is None:
            user_info = self.endpoint_context.userinfo(user_id, client_id=None)
            payload.update(user_info)
        elif claims_restriction == {}:  # Nothing is allowed
            pass
        else:
            possible_claims = self._get_client_claims(client_id)
            if self.add_claims_by_scope:
                _claims = convert_scopes2claims(scopes, map=self.scope_claims_map).keys()
                possible_claims = list(set(possible_claims).union(_claims))

            if possible_claims:
                _claims = {c: None for c in
                           set(possible_claims).intersection(set(claims_restriction.key()))}
                _claims.update(claims_restriction)
            else:
                _claims = claims_restriction

            if _claims:
                user_info = self.endpoint_context.userinfo(user_id, client_id=None,
                                                           user_info_claims=_claims)
                for attr in _claims:
                    try:
                        payload[attr] = user_info[attr]
                    except KeyError:
                        pass


class JWTToken(Token):
    def __init__(
            self,
            typ,
            keyjar=None,
            issuer: str = None,
            aud: Optional[list] = None,
            alg: str = "ES256",
            lifetime: int = 300,
            ec=None,
            token_type: str = "Bearer",
            add_claims: bool = False,
            add_scope: bool = False,
            **kwargs
            ):
        Token.__init__(self, typ, **kwargs)
        self.token_type = token_type
        self.lifetime = lifetime
        self.claims_interface = ClaimsInterface(ec, **kwargs)

        self.args = {
            (k, v) for k, v in kwargs.items() if k not in self.claims_interface.init_args.keys()
            }

        self.key_jar = keyjar or ec.keyjar
        self.issuer = issuer or ec.issuer
        self.cdb = ec.cdb
        self.cntx = ec

        self.def_aud = aud or []
        self.alg = alg
        self.add_scope = add_scope
        self.add_claims = add_claims

    def __call__(
            self,
            sid: str,
            **kwargs
            ):
        """
        Return a token.

        :param sid: Session id
        :return: Signed JSON Web Token
        """

        payload = {"sid": sid, "ttype": self.type, "sub": kwargs['sub']}

        _scopes = kwargs.get('scope')
        _client_id = kwargs.get('client_id')
        _user_id = kwargs.get('user_id')
        _claims = kwargs.get('claims')

        if self.add_claims:
            self.claims_interface.add_claims(_client_id, _user_id, payload, claims=_claims,
                                             scopes=_scopes)
        if self.add_scope:
            payload["scope"] = self.cntx.scopes_handler.filter_scopes(
                client_id, self.cntx, scopes
            )

        # payload.update(kwargs)
        signer = JWT(
            key_jar=self.key_jar,
            iss=self.issuer,
            lifetime=self.lifetime,
            sign_alg=self.alg,
            )

        _aud = kwargs.get('aud')
        if _aud is None:
            _aud = self.def_aud
        else:
            _aud = _aud if isinstance(_aud, list) else [_aud]
            _aud.extend(self.def_aud)

        return signer.pack(payload, aud=_aud)

    def info(self, token):
        """
        Return type of Token (A=Access code, T=Token, R=Refresh token) and
        the session id.

        :param token: A token
        :return: tuple of token type and session id
        """
        verifier = JWT(key_jar=self.key_jar, allowed_sign_algs=[self.alg])
        try:
            _payload = verifier.unpack(token)
        except JWSException:
            raise UnknownToken()

        if is_expired(_payload["exp"]):
            raise ToOld("Token has expired")
        # All the token metadata
        _res = {
            "sid": _payload["sid"],
            "type": _payload["ttype"],
            "exp": _payload["exp"],
            "handler": self,
            }
        return _res

    def is_expired(self, token, when=0):
        """
        Evaluate whether the token has expired or not

        :param token: The token
        :param when: The time against which to check the expiration
            0 means now.
        :return: True/False
        """
        verifier = JWT(key_jar=self.key_jar, allowed_sign_algs=[self.alg])
        _payload = verifier.unpack(token)
        return is_expired(_payload["exp"], when)

    def gather_args(self, sid, sdb, udb):
        _sinfo = sdb[sid]
        return {}
