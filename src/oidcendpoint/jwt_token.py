from cryptojwt import JWT

from oidcendpoint.exception import ToOld
from oidcendpoint.token_handler import is_expired


class JWTToken(object):
    def __init__(self, typ, keyjar, issuer, aud, alg='ES256', lifetime=300,
                 **kwargs):
        self.type = typ
        self.lifetime = lifetime
        self.args = kwargs
        self.key_jar = keyjar
        self.issuer = issuer
        self.def_aud = aud
        self.alg = alg

    def __call__(self, sid, aud, **kwargs):
        """
        Return a token.

        :param sid: Session id
        :return:
        """
        payload = {'sid': sid, 'ttype': self.type}
        signer = JWT(key_jar=self.key_jar, iss=self.issuer,
                     lifetime=self.lifetime, sign_alg=self.alg)
        return signer.pack(payload, aud=aud)

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
