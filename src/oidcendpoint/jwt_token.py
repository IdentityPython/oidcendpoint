from cryptojwt import JWT
from oidcmsg.oidc import scope2claims

from oidcendpoint.exception import ToOld
from oidcendpoint.token_handler import is_expired


class JWTToken(object):
    def __init__(self, typ, keyjar=None, issuer=None, aud=None, alg='ES256',
                 lifetime=300, ec=None, token_type='Bearer',**kwargs):
        self.type = typ
        self.token_type = token_type
        self.lifetime = lifetime
        self.args = kwargs

        self.key_jar = keyjar or ec.keyjar
        self.issuer = issuer or ec.issuer

        self.def_aud = aud or []
        self.alg = alg

    def add_claims(self, payload, uinfo, claims):
        for attr in claims:
            if attr == 'sub':
                continue
            try:
                payload[attr] = uinfo[attr]
            except KeyError:
                pass

    def __call__(self, sid, aud, uinfo, sinfo, **kwargs):
        """
        Return a token.

        :param sid: Session id
        :return:
        """
        payload = {'sid': sid, 'ttype': self.type, 'sub': sinfo['sub']}

        if 'add_claims' in self.args:
            self.add_claims(payload, uinfo, self.args['add_claims'])
        if 'add_claims_by_scope':
            self.add_claims(payload, uinfo,
                            scope2claims(sinfo["authn_req"]["scope"]).keys())

        payload.update(kwargs)
        signer = JWT(key_jar=self.key_jar, iss=self.issuer,
                     lifetime=self.lifetime, sign_alg=self.alg)
        _aud = [aud]
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
        if is_expired(_payload['exp']):
            raise ToOld('Token has expired')
        return _payload['sid'], _payload['ttype']

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
        return is_expired(_payload['exp'], when)

    def gather_args(self, sid, sdb, udb):
        _sinfo = sdb[sid]
        return {}
