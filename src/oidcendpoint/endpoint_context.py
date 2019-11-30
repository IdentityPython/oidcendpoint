import logging
import os

import requests
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import init_key_jar
from jinja2 import Environment
from jinja2 import FileSystemLoader
from oidcmsg.oidc import IdToken

from oidcendpoint import authz
from oidcendpoint import rndstr
from oidcendpoint import util
from oidcendpoint.client_authn import CLIENT_AUTHN_METHOD
from oidcendpoint.id_token import IDToken
from oidcendpoint.session import create_session_db
from oidcendpoint.sso_db import SSODb
from oidcendpoint.template_handler import Jinja2TemplateHandler
from oidcendpoint.user_authn.authn_context import populate_authn_broker
from oidcendpoint.user_info import SCOPE2CLAIMS
from oidcendpoint.util import build_endpoints
from oidcendpoint.util import importer

logger = logging.getLogger(__name__)


def add_path(url, path):
    if url.endswith("/"):
        if path.startswith("/"):
            return "{}{}".format(url, path[1:])

        return "{}{}".format(url, path)

    if path.startswith("/"):
        return "{}{}".format(url, path)

    return "{}/{}".format(url, path)


def init_user_info(conf, cwd):
    try:
        kwargs = conf["kwargs"]
    except KeyError:
        kwargs = {}

    if "db_file" in kwargs:
        kwargs["db_file"] = os.path.join(cwd, kwargs["db_file"])

    if isinstance(conf["class"], str):
        return util.importer(conf["class"])(**kwargs)

    return conf["class"](**kwargs)


def init_service(conf, endpoint_context=None):
    try:
        kwargs = conf["kwargs"]
    except KeyError:
        kwargs = {}

    if endpoint_context:
        kwargs["endpoint_context"] = endpoint_context

    if isinstance(conf["class"], str):
        return util.importer(conf["class"])(**kwargs)

    return conf["class"](**kwargs)


def get_token_handlers(conf):
    th_args = conf.get("token_handler_args", None)
    if not th_args:
        # create 3 keys
        keydef = [
            {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"},
            {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "token"},
            {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "refresh"},
        ]

        jwks_def = {
            "private_path": "private/token_jwks.json",
            "key_defs": keydef,
            "read_only": False,
        }
        th_args = {"jwks_def": jwks_def}
        for typ, tid in [("code", 600), ("token", 3600), ("refresh", 86400)]:
            th_args[typ] = {"lifetime": tid}

    return th_args


class EndpointContext:
    def __init__(
            self,
            conf,
            keyjar=None,
            client_db=None,
            session_db=None,
            sso_db=None,
            cwd="",
            cookie_dealer=None,
            httpc=None,
            cookie_name=None,
            jwks_uri_path=None,
    ):
        self.conf = conf
        self.keyjar = keyjar or KeyJar()
        self.cwd = cwd

        # client database
        self.cdb = client_db or {}

        try:
            self.seed = bytes(conf["seed"], "utf-8")
        except KeyError:
            self.seed = bytes(rndstr(16), "utf-8")

        # Default values, to be changed below depending on configuration
        self.endpoint = {}
        self.issuer = ""
        self.httpc = httpc or requests
        self.verify_ssl = True
        self.jwks_uri = None
        self.sso_ttl = 14400  # 4h
        self.symkey = rndstr(24)
        self.id_token_schema = IdToken
        self.idtoken = None
        self.authn_broker = None
        self.authz = None
        self.endpoint_to_authn_method = {}
        self.cookie_dealer = cookie_dealer
        self.login_hint_lookup = None
        self.login_hint2acrs = None
        self.userinfo = None
        # arguments for endpoints add-ons
        self.args = {}

        # session db
        self._sub_func = None
        self.sdb = session_db
        if not self.sdb:
            self.set_session_db(conf, sso_db)
        #

        self.scope2claims = SCOPE2CLAIMS

        if cookie_name:
            self.cookie_name = cookie_name
        elif "cookie_name" in conf:
            self.cookie_name = conf["cookie_name"]
        else:
            self.cookie_name = {
                "session": "oidcop",
                "register": "oidc_op_rp",
                "session_management": "sman",
            }

        for param in [
            "verify_ssl",
            "issuer",
            "sso_ttl",
            "symkey",
            "client_authn",
            "id_token_schema",
        ]:
            try:
                setattr(self, param, conf[param])
            except KeyError:
                pass

        try:
            self.template_handler = conf["template_handler"]
        except KeyError:
            try:
                loader = conf["template_loader"]
            except KeyError:
                template_dir = conf["template_dir"]
                loader = Environment(loader=FileSystemLoader(template_dir),
                                     autoescape=True)
            self.template_handler = Jinja2TemplateHandler(loader)

        self.setup = {}
        if not jwks_uri_path:
            try:
                jwks_uri_path = conf["jwks"]["uri_path"]
            except KeyError:
                pass

        try:
            if self.issuer.endswith("/"):
                self.jwks_uri = "{}{}".format(self.issuer, jwks_uri_path)
            else:
                self.jwks_uri = "{}/{}".format(self.issuer, jwks_uri_path)
        except KeyError:
            self.jwks_uri = ""

        if self.keyjar is None or self.keyjar.owners() == []:
            args = {k: v for k, v in conf["jwks"].items() if k != "uri_path"}
            self.keyjar = init_key_jar(**args)

        for item in ['cookie_dealer', "sub_func", "authz", "authentication",
                     "id_token", "scope2claims"]:
            _func = getattr(self, "do_{}".format(item), None)
            if _func:
                _func(self.conf)

        _cap = self.do_endpoints(conf)

        for item in ["userinfo", "login_hint_lookup", "login_hint2acrs",
                     "add_on"]:
            _func = getattr(self, "do_{}".format(item), None)
            if _func:
                _func(self.conf)

        self.provider_info = self.create_providerinfo(_cap)

        # which signing/encryption algorithms to use in what context
        self.jwx_def = {}

        # special type of logging
        self.events = None

        # client registration access tokens
        self.registration_access_token = {}

    def set_session_db(self, conf, sso_db=None):
        # this populate self.sdb
        sso_db = sso_db if sso_db else SSODb()
        self.do_session_db(conf, sso_db)
        # this append useinfo db to the session db
        self.do_userinfo(conf)
        logger.debug('Session DB: {}'.format(self.sdb.__dict__))

    def do_add_on(self, conf):
        if 'add_on' in conf:
            for spec in conf["add_on"].values():
                if isinstance(spec["function"], str):
                    _func = importer(spec["function"])
                else:
                    _func = spec["function"]

                _func(self.endpoint, **spec["kwargs"])

    def do_login_hint2acrs(self, conf):
        try:
            _conf = conf["login_hint2acrs"]
        except KeyError:
            self.login_hint2acrs = None
        else:
            self.login_hint2acrs = init_service(_conf)

    def do_login_hint_lookup(self, conf):
        try:
            _conf = conf["login_hint_lookup"]
        except KeyError:
            pass
        else:
            self.login_hint_lookup = init_service(_conf)
            if self.userinfo:
                self.login_hint_lookup.user_info = self.userinfo

    def do_userinfo(self, conf):
        try:
            _conf = conf["userinfo"]
        except KeyError:
            pass
        else:
            if self.sdb:
                self.userinfo = init_user_info(_conf, self.cwd)
                self.sdb.userinfo = self.userinfo


    def do_id_token(self, conf):
        try:
            _conf = conf["id_token"]
        except KeyError:
            self.idtoken = IDToken(self)
        else:
            self.idtoken = init_service(_conf, self)

    def do_authentication(self, conf):
        try:
            _authn = conf["authentication"]
        except KeyError:
            self.authn_broker = None
        else:
            self.authn_broker = populate_authn_broker(_authn, self, self.template_handler)

    def do_cookie_dealer(self, conf):
        try:
            _conf = conf['cookie_dealer']
        except KeyError:
            pass
        else:
            if not self.cookie_dealer:
                self.cookie_dealer = init_service(_conf)

    def do_sub_func(self, conf):
        _conf = conf.get("sub_func", {})
        self._sub_func = {}
        for key, args in _conf.items():
            if "class" in args:
                self._sub_func[key] = init_service(args)
            elif "function" in args:
                if isinstance(args["function"], str):
                    self._sub_func[key] = util.importer(args["function"])
                else:
                    self._sub_func[key] = args["function"]

    def do_session_db(self, conf, sso_db):
        th_args = get_token_handlers(conf)
        self.sdb = create_session_db(
            self, th_args, db=None,
            sso_db=sso_db,
            sub_func=self._sub_func
        )

    def do_endpoints(self, conf):
        self.endpoint = build_endpoints(
            conf["endpoint"],
            endpoint_context=self,
            client_authn_method=CLIENT_AUTHN_METHOD,
            issuer=conf["issuer"],
        )
        try:
            _cap = conf["capabilities"]
        except KeyError:
            _cap = {}

        for endpoint, endpoint_instance in self.endpoint.items():
            if endpoint_instance.provider_info:
                _cap.update(endpoint_instance.provider_info)

            if endpoint in ["webfinger", "provider_info"]:
                continue

            if endpoint_instance.endpoint_name:
                _cap[endpoint_instance.endpoint_name] = endpoint_instance.full_path

        return _cap

    def do_authz(self, conf):
        try:
            authz_spec = conf["authz"]
        except KeyError:
            self.authz = authz.Implicit(self)
        else:
            self.authz = init_service(authz_spec, self)

    def claims_supported(self):
        _claims = set()
        for scope, claims in self.scope2claims.items():
            _claims.update(set(claims))
        return list(_claims)

    def create_providerinfo(self, capabilities):
        """
        Dynamically create the provider info response

        :param capabilities:
        :return:
        """

        _provider_info = capabilities
        _provider_info["issuer"] = self.issuer
        _provider_info["version"] = "3.0"

        # acr_values
        if self.authn_broker:
            acr_values = self.authn_broker.get_acr_values()
            if acr_values is not None:
                _provider_info["acr_values_supported"] = acr_values

        if self.jwks_uri and self.keyjar:
            _provider_info["jwks_uri"] = self.jwks_uri

        _provider_info.update(self.idtoken.provider_info)
        _provider_info['claims_supported'] = self.claims_supported()

        return _provider_info
