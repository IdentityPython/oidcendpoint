from typing import Optional

from cryptojwt import JWT
from cryptojwt.jws.exception import JWSException

from oidcendpoint.exception import ToOld
from oidcendpoint.session_management import db_key
from oidcendpoint.token_handler import Token
from oidcendpoint.token_handler import UnknownToken
from oidcendpoint.token_handler import is_expired
from oidcendpoint.userinfo import ClaimsInterface


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
            **kwargs
    ):
        Token.__init__(self, typ, **kwargs)
        self.token_type = token_type
        self.lifetime = lifetime
        self.claims_interface = ClaimsInterface(ec, "jwt_token", **kwargs)

        self.args = {
            (k, v) for k, v in kwargs.items() if k not in self.claims_interface.init_args.keys()
        }

        self.key_jar = keyjar or ec.keyjar
        self.issuer = issuer or ec.issuer
        self.cdb = ec.cdb
        self.cntx = ec

        self.def_aud = aud or []
        self.alg = alg
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
            grant = self.claims_interface.endpoint_context.session_manager.grants(sid)[0]
            user_info = self.claims_interface.get_user_claims(
                _user_id, grant.claims.get("id_token", {}))
            payload.update(user_info)

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
