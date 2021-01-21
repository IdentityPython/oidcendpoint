from typing import Optional

from cryptojwt import JWT
from cryptojwt.jws.exception import JWSException

from oidcendpoint.exception import ToOld

from . import Token
from . import is_expired
from .exception import UnknownToken

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
            endpoint_context=None,
            token_type: str = "Bearer",
            **kwargs
    ):
        Token.__init__(self, typ, **kwargs)
        self.token_type = token_type
        self.lifetime = lifetime

        self.kwargs = kwargs
        self.key_jar = keyjar or endpoint_context.keyjar
        self.issuer = issuer or endpoint_context.issuer
        self.cdb = endpoint_context.cdb
        self.endpoint_context = endpoint_context

        self.def_aud = aud or []
        self.alg = alg

    def __call__(self, session_id: str, **kwargs):
        """
        Return a token.

        :param endpoint_context:
        :param session_id: Session id
        :return: Signed JSON Web Token
        """

        session_info = self.endpoint_context.session_manager.get_session_info(
            session_id, client_session_info=True, grant=True)
        sub = session_info["client_session_info"]["sub"]
        payload = {"sid": session_id, "ttype": self.type, "sub": sub}

        grant = session_info["grant"]
        _claims_restriction = grant.claims.get("token")
        if _claims_restriction:
            user_info = self.endpoint_context.claims_interface.get_user_claims(
                session_info["user_id"], _claims_restriction)
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
            _aud = grant.resources
        else:
            _aud = _aud if isinstance(_aud, list) else [_aud]
            _aud.extend(grant.resources)

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
