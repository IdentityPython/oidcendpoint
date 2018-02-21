import hashlib
import hmac
import json
import logging
from random import random
from urllib.parse import parse_qs
from urllib.parse import splitquery
from urllib.parse import urlencode
from urllib.parse import urljoin
from urllib.parse import urlparse

import time
from jwkest import jws
from oiccli import sanitize, rndstr
from oiccli.exception import CapabilitiesMisMatch
from oicmsg.exception import MessageException
from oicmsg.oauth2 import ErrorResponse
from oicmsg.oic import ClientRegistrationErrorResponse
from oicmsg.oic import RegistrationRequest
from oicmsg.oic import RegistrationResponse
from oicmsg.time_util import utc_time_sans_frac

from oicsrv.endpoint import Endpoint
from oicsrv.exception import InvalidRedirectURIError
from oicsrv.exception import InvalidSectorIdentifier

PREFERENCE2PROVIDER = {
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg":
        "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc":
        "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg":
        "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc":
        "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg":
        "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc":
        "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg":
        "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported",
    'grant_types': 'grant_types_supported'
}

logger = logging.getLogger(__name__)


def match_sp_sep(first, second):
    one = [set(v.split(" ")) for v in first]
    other = [set(v.split(" ")) for v in second]
    if not any(rt in one for rt in other):
        return False
    return True


def verify_url(url, urlset):
    part = urlparse(url)

    for reg, qp in urlset:
        _part = urlparse(reg)
        if part.scheme == _part.scheme and part.netloc == _part.netloc:
            return True

    return False


def client_secret_expiration_time():
    '''
    Returns client_secret expiration time.

    Split for easy customization.
    '''
    return utc_time_sans_frac() + 86400


def secret(seed, sid):
    msg = "{}{:.6f}{}".format(time.time(), random(), sid).encode("utf-8")
    csum = hmac.new(seed, msg, hashlib.sha224)
    return csum.hexdigest()


class Registration(Endpoint):
    request_cls = RegistrationRequest
    response_cls = RegistrationResponse
    error_response = ClientRegistrationErrorResponse
    request_format = 'json'
    request_placement = 'body'
    response_format = 'json'

    # default
    # response_placement = 'body'

    @staticmethod
    def match_client_request(srv_info, request):
        for _pref, _prov in PREFERENCE2PROVIDER.items():
            if _pref in request:
                if _pref == "response_types":
                    if not match_sp_sep(request[_pref],
                                        srv_info.provider_info[_prov]):
                        raise CapabilitiesMisMatch(_pref)
                else:
                    if isinstance(request[_pref], str):
                        if request[_pref] not in srv_info.provider_info[_prov]:
                            raise CapabilitiesMisMatch(_pref)
                    else:
                        if not set(request[_pref]).issubset(
                                set(srv_info.provider_info[_prov])):
                            raise CapabilitiesMisMatch(_pref)

    def do_client_registration(self, srv_info, request, client_id, ignore=None):
        if ignore is None:
            ignore = []

        _cinfo = srv_info.cdb[client_id].copy()
        logger.debug("_cinfo: %s" % sanitize(_cinfo))

        for key, val in request.items():
            if key not in ignore:
                _cinfo[key] = val

        if "post_logout_redirect_uris" in request:
            plruri = []
            for uri in request["post_logout_redirect_uris"]:
                if urlparse(uri).fragment:
                    err = ClientRegistrationErrorResponse(
                        error="invalid_configuration_parameter",
                        error_description="post_logout_redirect_uris "
                                          "contains "
                                          "fragment")
                    return err
                base, query = splitquery(uri)
                if query:
                    plruri.append((base, parse_qs(query)))
                else:
                    plruri.append((base, query))
            _cinfo["post_logout_redirect_uris"] = plruri

        if "redirect_uris" in request:
            try:
                ruri = self.verify_redirect_uris(request)
                _cinfo["redirect_uris"] = ruri
            except InvalidRedirectURIError as e:
                return ClientRegistrationErrorResponse(
                    error="invalid_redirect_uri", error_description=str(e))

        if "sector_identifier_uri" in request:
            try:
                _cinfo["si_redirects"], _cinfo[
                    "sector_id"] = self._verify_sector_identifier(srv_info,
                                                                  request)
            except InvalidSectorIdentifier as err:
                return ErrorResponse(error="invalid_configuration_parameter",
                                     error_description=err)
        elif "redirect_uris" in request:
            if len(request["redirect_uris"]) > 1:
                # check that the hostnames are the same
                host = ""
                for url in request["redirect_uris"]:
                    part = urlparse(url)
                    _host = part.netloc.split(":")[0]
                    if not host:
                        host = _host
                    else:
                        try:
                            assert host == _host
                        except AssertionError:
                            return ErrorResponse(
                                error="invalid_configuration_parameter",
                                error_description="'sector_identifier_uri' "
                                                  "must be registered")

        for item in ["policy_uri", "logo_uri", "tos_uri"]:
            if item in request:
                if verify_url(request[item], _cinfo["redirect_uris"]):
                    _cinfo[item] = request[item]
                else:
                    return ErrorResponse(
                        error="invalid_configuration_parameter",
                        error_description="%s pointed to illegal URL" % item)

        # Do I have the necessary keys
        for item in ["id_token_signed_response_alg",
                     "userinfo_signed_response_alg"]:
            if item in request:
                if request[item] in srv_info.provider_info[
                    PREFERENCE2PROVIDER[item]]:
                    ktyp = jws.alg2keytype(request[item])
                    # do I have this ktyp and for EC type keys the curve
                    if ktyp not in ["none", "oct"]:
                        _k = self.keyjar.get_signing_key(ktyp,
                                                         alg=request[item])
                        if not _k:
                            del _cinfo[item]

        try:
            self.keyjar.load_keys(request, client_id)
            try:
                n_keys = len(self.keyjar[client_id])
                msg = "found {} keys for client_id={}"
                logger.debug(msg.format(n_keys, client_id))
            except KeyError:
                pass
        except Exception as err:
            logger.error(
                "Failed to load client keys: %s" % sanitize(request.to_dict()))
            logger.error("%s", err)
            logger.debug('Verify SSL: {}'.format(self.keyjar.verify_ssl))
            return ClientRegistrationErrorResponse(
                error="invalid_configuration_parameter",
                error_description="%s" % err)

        return _cinfo

    @staticmethod
    def verify_redirect_uris(registration_request):
        verified_redirect_uris = []
        try:
            client_type = registration_request["application_type"]
        except KeyError:  # default
            client_type = "web"

        if client_type == "web":
            try:
                if registration_request["response_types"] == ["code"]:
                    must_https = False
                else:  # one has to be implicit or hybrid
                    must_https = True
            except KeyError:
                must_https = True
        else:
            must_https = False

        for uri in registration_request["redirect_uris"]:
            p = urlparse(uri)
            if client_type == "native":
                if p.scheme not in ['http', 'https']:  # Custom scheme
                    pass
                elif p.scheme == "http" and p.hostname in ["localhost",
                                                           "127.0.0.1"]:
                    pass
                else:
                    logger.error("InvalidRedirectURI: scheme:%s, hostname:%s",
                                 p.scheme, p.hostname)
                    raise InvalidRedirectURIError(
                        "Redirect_uri must use custom scheme or http and "
                        "localhost")
            elif must_https and p.scheme != "https":
                raise InvalidRedirectURIError(
                    "None https redirect_uri not allowed")
            elif p.fragment:
                raise InvalidRedirectURIError("redirect_uri contains fragment")

            base, query = splitquery(uri)
            if query:
                verified_redirect_uris.append((base, parse_qs(query)))
            else:
                verified_redirect_uris.append((base, query))

        return verified_redirect_uris

    def _verify_sector_identifier(self, srv_info, request):
        """
        Verify `sector_identifier_uri` is reachable and that it contains 
        `redirect_uri`s.

        :param request: Provider registration request
        :return: si_redirects, sector_id
        :raises: InvalidSectorIdentifier
        """
        si_url = request["sector_identifier_uri"]
        try:
            res = srv_info.http(si_url)
        except ConnectionError as err:
            logger.error(err)
            res = None

        if not res:
            raise InvalidSectorIdentifier("Couldn't open sector_identifier_uri")

        logger.debug("sector_identifier_uri => %s", sanitize(res.text))

        try:
            si_redirects = json.loads(res.text)
        except ValueError:
            raise InvalidSectorIdentifier(
                "Error deserializing sector_identifier_uri content")

        if "redirect_uris" in request:
            logger.debug("redirect_uris: %s", request["redirect_uris"])
            for uri in request["redirect_uris"]:
                if uri not in si_redirects:
                    raise InvalidSectorIdentifier(
                        "redirect_uri missing from sector_identifiers")

        return si_redirects, si_url

    @staticmethod
    def comb_uri(args):
        for param in ["redirect_uris", "post_logout_redirect_uris"]:
            if param not in args:
                continue

            val = []
            for base, query_dict in args[param]:
                if query_dict:
                    query_string = urlencode(
                        [(key, v) for key in query_dict for v in
                         query_dict[key]])
                    val.append("%s?%s" % (base, query_string))
                else:
                    val.append(base)

            args[param] = val

    def client_registration_setup(self, srv_info, request):
        try:
            request.verify()
        except MessageException as err:
            if "type" not in request:
                return ErrorResponse(error="invalid_type",
                                     error_description="%s" % err)
            else:
                return ErrorResponse(error="invalid_configuration_parameter",
                                     error_description="%s" % err)

        request.rm_blanks()
        try:
            self.match_client_request(srv_info, request)
        except CapabilitiesMisMatch as err:
            return ErrorResponse(
                error="invalid_request",
                error_description="Don't support proposed %s" % err)

        # create new id och secret
        client_id = rndstr(12)
        while client_id in srv_info.cdb:
            client_id = rndstr(12)

        client_secret = secret(srv_info.seed, client_id)

        _rat = rndstr(32)
        reg_enp = srv_info.endpoint['registration'].endpoint_path.format(
            srv_info.issuer)

        srv_info.cdb[client_id] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "registration_access_token": _rat,
            "registration_client_uri": "%s?client_id=%s" % (reg_enp, client_id),
            "client_secret_expires_at": client_secret_expiration_time(),
            "client_id_issued_at": utc_time_sans_frac(),
            "client_salt": rndstr(8)
        }

        srv_info.cdb[_rat] = client_id

        _cinfo = self.do_client_registration(srv_info, request, client_id,
                                             ignore=["redirect_uris",
                                                     "policy_uri", "logo_uri",
                                                     "tos_uri"])
        if isinstance(_cinfo, ErrorResponse):
            return _cinfo

        args = dict([(k, v) for k, v in _cinfo.items()
                     if k in RegistrationResponse.c_param])

        self.comb_uri(args)
        response = RegistrationResponse(**args)

        # Add the client_secret as a symmetric key to the keyjar
        if client_secret:
            self.keyjar.add_symmetric(client_id, str(client_secret))

        srv_info.cdb[client_id] = _cinfo

        try:
            srv_info.cdb.sync()
        except AttributeError:  # Not all databases can be sync'ed
            pass

        logger.info("registration_response: %s" % sanitize(response.to_dict()))

        return response

    def process_request(self, srv_info, request=None, **kwargs):
        return {'response_args':
                    self.client_registration_setup(srv_info, request)}
