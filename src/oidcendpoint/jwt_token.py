from typing import Optional

from cryptojwt import JWT
from cryptojwt.jws.exception import JWSException

from oidcendpoint.exception import ToOld
from oidcendpoint.token_handler import Token
from oidcendpoint.token_handler import UnknownToken
from oidcendpoint.token_handler import is_expired

TYPE_MAP = {
    "A": "code",
    "T": "access_token",
    "R": "refresh_token"
}


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
            claims: Optional[list] = None,
            **kwargs
    ):
        Token.__init__(self, typ, **kwargs)
        self.token_type = token_type
        self.lifetime = lifetime

        self.args = kwargs
        self.key_jar = keyjar or ec.keyjar
        self.issuer = issuer or ec.issuer
        self.cdb = ec.cdb
        self.endpoint_context = ec

        self.def_aud = aud or []
        self.alg = alg
        self.add_scope = add_scope
        self.add_claims = add_claims
        self.claims = claims or []

    def __call__(
            self,
            sid: str,
            **kwargs
    ):
        """
        Return a token.

        :param endpoint_context:
        :param sid: Session id
        :return: Signed JSON Web Token
        """

        payload = {"sid": sid, "ttype": self.type, "sub": kwargs['sub']}

        session_info = self.endpoint_context.session_manager.get_session_info(sid)

        if self.add_claims:
            grant = session_info["grant"]
            _claims_restriction = grant.claims.get("introspection")
            if _claims_restriction:
                user_info = self.endpoint_context.claims_interface.get_user_claims(
                    session_info["user_id"], _claims_restriction)
                payload.update(user_info)
        if self.add_scope:
            payload["scope"] = self.claims_interface.endpoint_context.scopes_handler.filter_scopes(
                client_id, self.claims_interface.endpoint_context, scopes
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
