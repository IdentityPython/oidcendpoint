# coding=utf-8
import base64
import inspect
import json
import logging
import time
from urllib.parse import parse_qs
from urllib.parse import unquote
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from oidcmsg.jwt import JWT

from oidcendpoint import sanitize
from oidcendpoint.exception import FailedAuthentication
from oidcendpoint.exception import ImproperlyConfigured
from oidcendpoint.exception import InstantiationError
from oidcendpoint.exception import ToOld
from oidcendpoint.cookie import CookieDealer
from oidcendpoint.cookie import InvalidCookieSign

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

LOC = {
    "en": {
        "title": "User log in",
        "login_title": "Username",
        "passwd_title": "Password",
        "submit_text": "Submit",
        "client_policy_title": "Client Policy"},
    "se": {
        "title": "Logga in",
        "login_title": u"Användarnamn",
        "passwd_title": u"Lösenord",
        "submit_text": u"Sänd",
        "client_policy_title": "Klientens sekretesspolicy"
    }
}


class UserAuthnMethod(CookieDealer):
    MULTI_AUTH_COOKIE = "rp_query_cookie"

    # override in subclass specifying suitable url endpoint to POST user input
    url_endpoint = '/verify'
    FAILED_AUTHN = (None, True)

    def __init__(self, ttl=5, endpoint_context=None):
        CookieDealer.__init__(self, endpoint_context, ttl)
        self.query_param = "upm_answer"

    def __call__(self, **kwargs):
        """
        Display user interaction.

        :param args:
        :param kwargs:
        :return:
        """
        raise NotImplemented

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie is None:
            return None, 0
        else:
            logger.debug("kwargs: %s" % sanitize(kwargs))

            try:
                val = self.get_cookie_value(cookie,
                                            self.endpoint_context.cookie_name)
            except (InvalidCookieSign, AssertionError):
                val = None

            if val is None:
                return None, 0
            else:
                uid, _ts, typ = val

            if typ == "uam":  # short lived
                _now = int(time.time())
                if _now > (int(_ts) + int(self.cookie_ttl * 60)):
                    logger.debug("Authentication timed out")
                    raise ToOld("%d > (%d + %d)" % (_now, int(_ts),
                                                    int(self.cookie_ttl * 60)))
            else:
                if "max_age" in kwargs and kwargs["max_age"]:
                    _now = int(time.time())
                    if _now > (int(_ts) + int(kwargs["max_age"])):
                        logger.debug("Authentication too old")
                        raise ToOld("%d > (%d + %d)" % (
                            _now, int(_ts), int(kwargs["max_age"])))

            return {"uid": uid}, _ts

    def generate_return_url(self, return_to, uid, path=""):
        """
        :param return_to: If it starts with '/' it's an absolute path otherwise
        a relative path.
        :param uid:
        :param path: The verify path
        """
        if return_to.startswith("http"):
            up = urlsplit(return_to)
            _path = up.path
        else:
            up = None
            _path = return_to

        if not _path.startswith("/"):
            p = path.split("/")
            p[-1] = _path
            _path = "/".join(p)

        if up:
            _path = urlunsplit([up[0], up[1], _path, up[3], up[4]])

        return create_return_url(_path, uid, **{self.query_param: "true"})

    def verify(self, *args, **kwargs):
        """
        Callback to verify user input
        :return: username of the authenticated user
        """
        raise NotImplemented

    def get_multi_auth_cookie(self, cookie):
        rp_query_cookie = self.get_cookie_value(
            cookie, UserAuthnMethod.MULTI_AUTH_COOKIE)

        if rp_query_cookie:
            return rp_query_cookie[0]
        return ""


def url_encode_params(params=None):
    if not isinstance(params, dict):
        raise InstantiationError("You must pass in a dictionary!")
    params_list = []
    for k, v in params.items():
        if isinstance(v, list):
            params_list.extend([(k, x) for x in v])
        else:
            params_list.append((k, v))
    return urlencode(params_list)


def create_return_url(base, query, **kwargs):
    """
    Add a query string plus extra parameters to a base URL which may contain
    a query part already.

    :param base: redirect_uri may contain a query part, no fragment allowed.
    :param query: Old query part as a string
    :param kwargs: extra query parameters
    :return: Constructed URL
    """
    part = urlsplit(base)
    if part.fragment:
        raise ValueError("Base URL contained parts it shouldn't")

    for key, values in parse_qs(query).items():
        if key in kwargs:
            if isinstance(kwargs[key], str):
                kwargs[key] = [kwargs[key]]
            kwargs[key].extend(values)
        else:
            kwargs[key] = values

    if part.query:
        for key, values in parse_qs(part.query).items():
            if key in kwargs:
                if isinstance(kwargs[key], str):
                    kwargs[key] = [kwargs[key]]
                kwargs[key].extend(values)
            else:
                kwargs[key] = values

        _url_base = base.split("?")[0]
    else:
        _url_base = base

    logger.debug("kwargs: %s" % sanitize(kwargs))
    if kwargs:
        return "%s?%s" % (_url_base, url_encode_params(kwargs))
    else:
        return _url_base


def create_signed_jwt(issuer, keyjar, sign_alg='RS256', **kwargs):
    signer = JWT(keyjar, iss=issuer, sign_alg=sign_alg)
    return signer.pack(payload=kwargs)


def verify_signed_jwt(token, keyjar):
    verifier = JWT(keyjar)
    return verifier.unpack(token)


class UsernamePasswordMako(UserAuthnMethod):
    """Do user authentication using the normal username password form in a
    WSGI environment using Mako as template system"""

    url_endpoint = "/verify/user_pass_mako"
    param_map = {"as_user": "login", "acr_values": "acr",
                 "policy_uri": "policy_uri", "logo_uri": "logo_uri",
                 "tos_uri": "tos_uri", "query": "query"}

    def __init__(self, mako_template, template_lookup, pwd,
                 return_to="", templ_arg_func=None,
                 verification_endpoints=None, endpoint_context=None):
        """
        :param endpoint_context: The endpoint context
        :param mako_template: Which Mako template to use
        :param pwd: Username/password dictionary like database
        :param return_to: Where to send the user after authentication
        :return:
        """
        UserAuthnMethod.__init__(self, endpoint_context)
        self.mako_template = mako_template
        self.template_lookup = template_lookup
        self.passwd = pwd
        self.return_to = return_to
        self.verification_endpoints = verification_endpoints or ["verify"]
        if templ_arg_func:
            self.templ_arg_func = templ_arg_func
        else:
            self.templ_arg_func = self.template_args

    def template_args(self, end_point_index=0, **kwargs):
        """
        Method to override if necessary, dependent on the page layout
        and context

        :param end_point_index: An index into the list of verification endpoints
        :param kwargs: Extra keyword arguments
        :return: dictionary of parameters used to build the Authn page
        """

        try:
            action = kwargs["action"]
        except KeyError:
            action = self.verification_endpoints[end_point_index]

        argv = {"password": "", "action": action}

        for fro, to in self.param_map.items():
            try:
                argv[to] = kwargs[fro]
            except KeyError:
                argv[to] = ""

        if "extra" in kwargs:
            for param in kwargs["extra"]:
                try:
                    argv[param] = kwargs[param]
                except KeyError:
                    argv[param] = ""

        try:
            _locs = kwargs["ui_locales"]
        except KeyError:
            argv.update(LOC["en"])
        else:
            for loc in _locs:
                try:
                    argv.update(LOC[loc])
                except KeyError:
                    pass
                else:
                    break

        return argv

    def __call__(self, cookie=None, end_point_index=0, **kwargs):
        """
        Put up the login form
        """

        argv = self.templ_arg_func(end_point_index, **kwargs)
        logger.info("do_authentication argv: %s" % sanitize(argv))
        mte = self.template_lookup.get_template(self.mako_template)
        return {'response', mte.render(**argv).decode("utf-8")}

    def _verify(self, pwd, user):
        if pwd != self.passwd[user]:
            raise ValueError("Passwords don't match.")

    def verify(self, request, **kwargs):
        """
        Verifies that the given username and password was correct
        :param request: Either the query part of a URL a urlencoded
        body of a HTTP message or a parse such.
        :param kwargs: Catch whatever else is sent.
        :return: redirect back to where ever the base applications
        wants the user after authentication.
        """

        logger.debug("verify(%s)" % sanitize(request))
        _dict = request

        logger.debug("dict: %s" % sanitize(_dict))
        # verify username and password
        try:
            self._verify(_dict["password"], _dict["login"])  # dict origin
        except TypeError:
            try:
                self._verify(_dict["password"][0], _dict["login"][0])
            except (AssertionError, KeyError) as err:
                logger.debug("Password verification failed: {}".format(err))
                return {'response', b"Unknown user or wrong password"}
            else:
                try:
                    _qp = _dict["query"]
                except KeyError:
                    _qp = self.get_multi_auth_cookie(kwargs['cookie'])
        except (AssertionError, KeyError) as err:
            logger.debug("Password verification failed: {}".format(err))
            return {'response': b"Unknown user or wrong password"}
        else:
            try:
                _qp = _dict["query"]
            except KeyError:
                _qp = self.get_multi_auth_cookie(kwargs['cookie'])

        logger.debug("Password verification succeeded.")
        # if "cookie" not in kwargs or self.endpoint_context.cookie_name not in
        # kwargs["cookie"]:
        headers = [self.create_cookie(_dict["login"], "upm")]
        try:
            return_to = self.generate_return_url(kwargs["return_to"], _qp)
        except KeyError:
            try:
                return_to = self.generate_return_url(self.return_to, _qp,
                                                     kwargs["path"])
            except KeyError:
                return_to = self.generate_return_url(self.return_to, _qp)

        return {'redirect': return_to, 'headers': headers}

    def done(self, areq):
        """

        :param areq: Authentication request
        :return: True if the 'query_parameter' doesn't appear in the request
        """
        try:
            _ = areq[self.query_param]
        except KeyError:
            return True
        else:
            return False


class UserPassJinja2(UserAuthnMethod):
    url_endpoint = "/verify/user_pass_jinja"

    def __init__(self, db, template_env, template="user_pass.jinja2", **kwargs):
        super(UserPassJinja2, self).__init__()
        self.template_env = template_env
        self.template = template

        self.user_db = db["class"](**db["kwargs"])

        self.kwargs = kwargs
        self.kwargs.setdefault("page_header", "Log in")
        self.kwargs.setdefault("user_label", "Username")
        self.kwargs.setdefault("passwd_label", "Password")
        self.kwargs.setdefault("submit_btn", "Log in")

    def __call__(self, **kwargs):
        template = self.template_env.get_template(self.template)
        _ec = self.endpoint_context
        jws = create_signed_jwt(_ec.issuer, _ec.keyjar, **kwargs)
        return template.render(action=self.url_endpoint, token=jws,
                               **self.kwargs)

    def verify(self, *args, **kwargs):
        username = kwargs["username"]
        if username in self.user_db and self.user_db[username] == kwargs[
                "password"]:
            return username
        else:
            raise FailedAuthentication()

    def unpack_token(self, token):
        return verify_signed_jwt(token=token,
                                 keyjar=self.endpoint_context.keyjar)


class BasicAuthn(UserAuthnMethod):

    def __init__(self, pwd, ttl=5, endpoint_context=None):
        UserAuthnMethod.__init__(self, ttl, endpoint_context)
        self.passwd = pwd

    def verify_password(self, user, password):
        try:
            assert password == self.passwd[user]
        except (AssertionError, KeyError):
            raise FailedAuthentication("Wrong password")

    def authenticated_as(self, cookie=None, authorization="", **kwargs):
        """

        :param cookie: A HTTP Cookie
        :param authorization: The HTTP Authorization header
        :param kwargs: extra key word arguments
        :return:
        """
        if authorization.startswith("Basic"):
            authorization = authorization[6:]

        (user, pwd) = base64.b64decode(authorization).split(":")
        user = unquote(user)
        self.verify_password(user, pwd)
        return {"uid": user}, time.time()


class SymKeyAuthn(UserAuthnMethod):
    # user authentication using a token

    def __init__(self, ttl, symkey, endpoint_context=None):
        UserAuthnMethod.__init__(self, ttl, endpoint_context)

        if symkey is not None and symkey == "":
            msg = "SymKeyAuthn.symkey cannot be an empty value"
            raise ImproperlyConfigured(msg)
        self.symkey = symkey

    def authenticated_as(self, cookie=None, authorization="", **kwargs):
        """

        :param cookie: A HTTP Cookie
        :param authorization: The HTTP Authorization header
        :param kwargs: extra key word arguments
        :return:
        """
        (encmsg, iv) = base64.b64decode(authorization).split(":")
        try:
            aesgcm = AESGCM(self.symkey)
            user = aesgcm.decrypt(iv, encmsg, None)
        except (AssertionError, KeyError):
            raise FailedAuthentication("Decryption failed")

        return {"uid": user}, time.time()


class NoAuthn(UserAuthnMethod):
    # Just for testing allows anyone it without authentication

    def __init__(self, user, endpoint_context=None):
        UserAuthnMethod.__init__(self, endpoint_context)
        self.user = user

    def authenticated_as(self, cookie=None, authorization="", **kwargs):
        """

        :param cookie: A HTTP Cookie
        :param authorization: The HTTP Authorization header
        :param kwargs: extra key word arguments
        :return:
        """

        return {"uid": self.user}, time.time()


def factory(cls, **kwargs):
    """
    Factory method that can be used to easily instantiate a class instance

    :param cls: The name of the class
    :param kwargs: Keyword arguments
    :return: An instance of the class or None if the name doesn't match any
        known class.
    """
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, UserAuthnMethod):
            try:
                if obj.__name__ == cls:
                    return obj(**kwargs)
            except AttributeError:
                pass
