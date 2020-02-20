from typing import Any
from typing import Dict
from typing import Optional

from cryptojwt import JWT

from oidcendpoint.exception import ToOld
from oidcendpoint.token_handler import Token
from oidcendpoint.token_handler import is_expired
from oidcendpoint.user_info import scope2claims


class JWTToken(Token):
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
        self.args = kwargs

        self.key_jar = keyjar or ec.keyjar
        self.issuer = issuer or ec.issuer

        self.def_aud = aud or []
        self.alg = alg
        self.scope_claims_map = kwargs.get("scope_claims_map", ec.scope2claims)

    def add_claims(self, payload, uinfo, claims):
        for attr in claims:
            if attr == "sub":
                continue
            try:
                payload[attr] = uinfo[attr]
            except KeyError:
                pass

    def __call__(
        self, sid: str, uinfo: Dict, sinfo: Dict, *args, aud: Optional[Any], **kwargs
    ):
        """
        Return a token.

        :param sid: Session id
        :param uinfo: User information
        :param sinfo: Session information
        :param aud: The default audience == client_id
        :return:
        """
        payload = {"sid": sid, "ttype": self.type, "sub": sinfo["sub"]}

        if "add_claims" in self.args:
            self.add_claims(payload, uinfo, self.args["add_claims"])
        if self.args.get("add_claims_by_scope", False):
            self.add_claims(
                payload,
                uinfo,
                scope2claims(
                    sinfo["authn_req"]["scope"], map=self.scope_claims_map
                ).keys(),
            )

        payload.update(kwargs)
        signer = JWT(
            key_jar=self.key_jar,
            iss=self.issuer,
            lifetime=self.lifetime,
            sign_alg=self.alg,
        )

        if aud is None:
            _aud = self.def_aud
        else:
            _aud = aud if isinstance(aud, list) else [aud]
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
        _payload = verifier.unpack(token)

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
