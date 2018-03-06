import base64
import hashlib
import logging

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

from cryptojwt import as_bytes
from cryptojwt import as_unicode

from oidcmsg.time_util import time_sans_frac

from oidcendpoint import rndstr

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


def lv_pack(*args):
    s = []
    for a in args:
        s.append('{}:{}'.format(len(a), a))
    return ''.join(s)


def lv_unpack(txt):
    txt = txt.strip()
    res = []
    while txt:
        l, v = txt.split(':', 1)
        res.append(v[:int(l)])
        txt = v[int(l):]
    return res


class ExpiredToken(Exception):
    pass


class WrongTokenType(Exception):
    pass


class AccessCodeUsed(Exception):
    pass


class UnknownToken(Exception):
    pass


class NotAllowed(Exception):
    pass


def is_expired(exp, when=0):
    if exp < 0:
        return False

    if not when:
        when = time_sans_frac()
    return when > exp


class Crypt(object):
    def __init__(self, password, mode=None):
        self.key = base64.urlsafe_b64encode(
            hashlib.sha256(password.encode("utf-8")).digest())
        self.core = Fernet(self.key)

    def encrypt(self, text):
        # Padding to blocksize of AES
        text = as_bytes(text)
        if len(text) % 16:
            text += b' ' * (16 - len(text) % 16)
        return self.core.encrypt(as_bytes(text))

    def decrypt(self, ciphertext):
        dec_text = self.core.decrypt(ciphertext)
        dec_text = dec_text.rstrip(b' ')
        return as_unicode(dec_text)


class Token(object):
    def __init__(self, typ, lifetime=300, **kwargs):
        self.type = typ
        self.lifetime = lifetime
        self.args = kwargs

    def __call__(self, sid, *args, **kwargs):
        """
        Return a token.

        :param sid: Session id
        :return:
        """
        raise NotImplementedError()

    def key(self, **kwargs):
        """
        Return a key (the session id)
        """
        return rndstr(32)

    def info(self, token):
        """
        Return type of Token (A=Access code, T=Token, R=Refresh token) and
        the session id.

        :param token: A token
        :return: tuple of token type and session id
        """
        raise NotImplementedError()


class DefaultToken(Token):
    def __init__(self, password, typ='', black_list=None, token_type='Bearer',
                 **kwargs):
        Token.__init__(self, typ, **kwargs)
        self.crypt = Crypt(password)
        self.token_type = token_type
        self.blist = [] if black_list is None else black_list

    def __call__(self, sid='', ttype='', **kwargs):
        """
        Return a token.

        :param ttype: Type of token
        :param prev: Previous token, if there is one to go from
        :param sid: Session id
        :return:
        """
        if not ttype and self.type:
            ttype = self.type
        else:
            ttype = 'A'

        if self.lifetime >= 0:
            exp = str(time_sans_frac() + self.lifetime)
        else:
            exp = '-1'  # Live for ever

        tmp = ''
        rnd = ''
        while rnd == tmp:  # Don't use the same random value again
            rnd = rndstr(32)  # Ultimate length multiple of 16

        return base64.b64encode(
            self.crypt.encrypt(lv_pack(rnd, ttype, sid, exp).encode())).decode(
            "utf-8")

    def key(self, user="", areq=None):
        """
        Return a key (the session id)

        :param user: User id
        :param areq: The authorization request
        :return: An ID
        """
        csum = hashlib.new('sha224')
        csum.update(rndstr(32).encode('utf-8'))
        return csum.hexdigest()  # 56 bytes long, 224 bits

    def split_token(self, token):
        try:
            plain = self.crypt.decrypt(base64.b64decode(token))
        except Exception:
            raise UnknownToken(token)
        # order: rnd, type, sid
        return lv_unpack(plain)

    def info(self, token):
        """
        Return token information.

        :param token: A token
        :return: dictionary with info about the token
        """
        _res = dict(zip(['_id', 'type', 'sid', 'exp'],
                        self.split_token(token)))
        if _res['type'] != self.type:
            raise WrongTokenType(_res['type'])
        else:
            _res['handler'] = self
            _res['black_listed'] = self.is_black_listed(token)
            return _res

    def is_expired(self, token, when=0):
        _exp = self.info(token)['exp']
        if _exp == '-1':
            return False
        else:
            exp = int(_exp)
        return is_expired(exp, when)

    def black_list(self, token):
        if token:
            self.blist.append(token)

    def is_black_listed(self, token):
        return token in self.blist


class TokenHandler(object):
    def __init__(self, access_token_handler=None, code_handler=None,
                 refresh_token_handler=None):

        self.handler = {
            'code': code_handler,
            'access_token': access_token_handler,
        }

        self.handler_order = ['code', 'access_token']

        if refresh_token_handler:
            self.handler['refresh_token'] = refresh_token_handler
            self.handler_order.append('refresh_token')

        # self.lifetime_policy = {}
        # self.token_policy = {}
        # for handler in self.handler_order:
        #     self.lifetime_policy[handler] = {}
        #     self.token_policy[handler] = {}

    def __getitem__(self, typ):
        return self.handler[typ]

    def __contains__(self, item):
        return item in self.handler

    def info(self, item, order=None):
        if order is None:
            order = self.handler_order

        for typ in order:
            try:
                return self.handler[typ].info(item)
            except (KeyError, WrongTokenType, InvalidToken, UnknownToken):
                pass

        logger.info("Unknown token format")
        raise KeyError(item)

    def sid(self, token, order=None):
        return self.info(token, order)['sid']

    def type(self, token, order=None):
        return self.info(token, order)['type']

    def is_black_listed(self, token,  order=None):
        _handler = self.get_handler(token, order)
        return _handler.is_black_listed(token)

    def get_handler(self, token, order=None):
        if order is None:
            order = self.handler_order

        for typ in order:
            try:
                self.handler[typ].info(token)
            except (KeyError, WrongTokenType, InvalidToken, UnknownToken):
                pass
            else:
                return self.handler[typ]

        return None

    def black_list(self, token, order=None):
        _handler = self.get_handler(token, order)
        _handler.black_list(token)

    def keys(self):
        return self.handler.keys()

    # def set_token_policy(self, cid, cinfo):
    #     for ttyp in ['access_token', 'refresh_token']:
    #         pol = {}
    #         for rgtyp in ['response_type', 'grant_type']:
    #             try:
    #                 rtyp = cinfo[rgtyp]
    #             except KeyError:
    #                 pass
    #             else:
    #                 for typ in rtyp:
    #                     try:
    #                         pol[typ] = self.lifetime_policy[ttyp][typ]
    #                     except KeyError:
    #                         pass
    #
    #         self.token_policy[ttyp][cid] = pol
