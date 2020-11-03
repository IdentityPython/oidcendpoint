from cryptojwt import JWT
from cryptojwt.jws.exception import JWSException

from oidcendpoint.exception import ToOld
from oidcendpoint.scopes import convert_scopes2claims
from oidcendpoint.token_handler import Token
from oidcendpoint.token_handler import UnknownToken
from oidcendpoint.token_handler import is_expired


class JWTToken(Token):
    init_args = {
        "add_claims_by_scope": False,
        "enable_claims_per_client": False,
        "add_scope": False,
        "add_claims": {},
    }

    def __init__(
            self,
            typ,
            keyjar=None,
            issuer=None,
            aud=None,
            alg="ES256",
            lifetime=300,
            ec=None,
            token_type="Bearer",
            **kwargs
    ):
        Token.__init__(self, typ, **kwargs)
        self.token_type = token_type
        self.lifetime = lifetime
        self.args = {
            (k, v) for k, v in kwargs.items() if k not in self.init_args.keys()
        }

        self.key_jar = keyjar or ec.keyjar
        self.issuer = issuer or ec.issuer
        self.cdb = ec.cdb
        self.cntx = ec

        self.def_aud = aud or []
        self.alg = alg
        self.scope_claims_map = kwargs.get("scope_claims_map", ec.scope2claims)

        self.add_claims = self.init_args["add_claims"]
        self.add_claims_by_scope = self.init_args["add_claims_by_scope"]
        self.add_scope = self.init_args["add_scope"]
        self.enable_claims_per_client = self.init_args["enable_claims_per_client"]

        for param, default in self.init_args.items():
            setattr(self, param, kwargs.get(param, default))

    def do_add_claims(self, payload, uinfo, claims):
        for attr in claims:
            if attr == "sub":
                continue
            try:
                payload[attr] = uinfo[attr]
            except KeyError:
                pass

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

        payload = {"sid": sid, "ttype": self.type, "sub": kwargs["sinfo"]["sub"]}

        _user_claims = kwargs.get('user_claims')
        _client_id = kwargs.get('client_id')
        _scopes = kwargs.get('scope')

        if self.add_claims:
            self.do_add_claims(payload, _user_claims, self.add_claims)
        if self.add_claims_by_scope:
            _allowed_claims = self.cntx.claims_handler.allowed_claims(_client_id, self.cntx)
            self.do_add_claims(
                payload,
                _user_claims,
                convert_scopes2claims(_scopes, _allowed_claims, map=self.scope_claims_map).keys(),
            )
        if self.add_scope:
            payload["scope"] = self.cntx.scopes_handler.filter_scopes(
                client_id, self.cntx, scopes
            )

        # Add claims if is access token
        if self.type == "T" and self.enable_claims_per_client:
            client = self.cdb.get(_client_id, {})
            client_claims = client.get("access_token_claims")
            if client_claims:
                self.do_add_claims(payload, _user_claims, client_claims)

        payload.update(kwargs)
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
