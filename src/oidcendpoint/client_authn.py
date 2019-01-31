import base64
import logging

from cryptojwt.exception import Invalid
from cryptojwt.exception import MissingKey
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode

from cryptojwt.jwt import JWT
from oidcmsg.oidc import AuthnToken

from oidcendpoint import JWT_BEARER
from oidcendpoint import rndstr
from oidcendpoint import sanitize
from oidcendpoint.exception import NotForMe

logger = logging.getLogger(__name__)

__author__ = 'roland hedberg'


class AuthnFailure(Exception):
    pass


class NoMatchingKey(Exception):
    pass


class UnknownOrNoAuthnMethod(Exception):
    pass


# ========================================================================
def assertion_jwt(cli, keys, audience, algorithm, lifetime=600):
    _now = utc_time_sans_frac()

    at = AuthnToken(iss=cli.client_id, sub=cli.client_id,
                    aud=audience, jti=rndstr(32),
                    exp=_now + lifetime, iat=_now)
    return at.to_jwt(key=keys, algorithm=algorithm)


class ClientAuthnMethod(object):
    def __init__(self, endpoint_context=None):
        """
        :param endpoint_context: Server info, a
            :py:class:`oidcendpoint.endpoint_context.EndpointContext` instance
        """
        self.endpoint_context = endpoint_context

    def verify(self, **kwargs):
        """
        Verify authentication information in a request
        :param kwargs:
        :return:
        """
        raise NotImplementedError


def basic_authn(authn):
    if not authn.startswith("Basic "):
        raise AuthnFailure("Wrong type of authorization token")

    (_id, _secret) = as_unicode(
        base64.b64decode(as_bytes(authn[6:]))).split(":")

    return {'id': _id, 'secret': _secret}


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.
    """

    def verify(self, request, authorization_info, **kwargs):
        client_info = basic_authn(authorization_info)

        if self.endpoint_context.cdb[
            client_info['id']]["client_secret"] == client_info['secret']:
            return {'client_id': client_info['id']}
        else:
            raise AuthnFailure()


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.
    """

    def verify(self, request, **kwargs):
        if self.endpoint_context.cdb[
                request[
                    'client_id']]["client_secret"] == request['client_secret']:
            return {'client_id': request['client_id']}
        else:
            raise AuthnFailure("secrets doesn't match")


class BearerHeader(ClientSecretBasic):
    """
    """

    def verify(self, request, authorization_info, **kwargs):
        if not authorization_info.startswith("Bearer "):
            raise AuthnFailure("Wrong type of authorization token")

        return {'token': authorization_info.split(' ', 1)[1]}


class BearerBody(ClientSecretPost):
    """
    Same as Client Secret Post
    """

    def verify(self, request, **kwargs):
        try:
            return {'token': request['access_token']}
        except KeyError:
            raise AuthnFailure('No access token')


class JWSAuthnMethod(ClientAuthnMethod):

    def verify(self, request, **kwargs):
        _jwt = JWT(self.endpoint_context.keyjar)
        try:
            ca_jwt = _jwt.unpack(request["client_assertion"])
        except (Invalid, MissingKey) as err:
            logger.info("%s" % sanitize(err))
            raise AuthnFailure("Could not verify client_assertion.")

        try:
            logger.debug("authntoken: %s" % sanitize(ca_jwt.to_dict()))
        except AttributeError:
            logger.debug("authntoken: %s" % sanitize(ca_jwt))

        request['parsed_client_assertion'] = ca_jwt

        try:
            client_id = kwargs["client_id"]
        except KeyError:
            client_id = ca_jwt["iss"]

        # I should be among the audience
        # could be either my issuer id or the token endpoint
        if self.endpoint_context.issuer in ca_jwt["aud"]:
            pass
        elif self.endpoint_context.endpoint['token'].full_path in ca_jwt['aud']:
            pass
        else:
            raise NotForMe("Not for me!")

        return {'client_id': client_id, 'jwt': ca_jwt}


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server create a JWT using an HMAC SHA algorithm, such as HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key sign a JWT using that key.
    """


CLIENT_AUTHN_METHOD = {
    "client_secret_basic": ClientSecretBasic,
    "client_secret_post": ClientSecretPost,
    "bearer_header": BearerHeader,
    "bearer_body": BearerBody,
    "client_secret_jwt": ClientSecretJWT,
    "private_key_jwt": PrivateKeyJWT,
}

TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)]


def valid_client_info(cinfo):
    eta = cinfo.get('client_secret_expires_at', 0)
    if eta != 0 and eta < utc_time_sans_frac():
        return False
    return True


def verify_client(endpoint_context, request, authorization_info):
    """
    Initiated Guessing !

    :param endpoint_context: SrvInfo instance
    :param request: The request
    :param authorization_info: Client authentication information
    :return: dictionary containing client id, client authentication method and
        possibly access token.
    """

    if not authorization_info:
        if 'client_id' in request and 'client_secret' in request:
            auth_info = ClientSecretPost(endpoint_context).verify(request)
            auth_info['method'] = 'client_secret_post'
        elif 'client_assertion' in request:
            auth_info = JWSAuthnMethod(endpoint_context).verify(request)
            #  If symmetric key was used
            # auth_method = 'client_secret_jwt'
            #  If asymmetric key was used
            auth_info['method'] = 'private_key_jwt'
        elif 'access_token' in request:
            auth_info = BearerBody(endpoint_context).verify(request)
            auth_info['method'] = 'bearer_body'
        else:
            raise UnknownOrNoAuthnMethod()
    else:
        if authorization_info.startswith('Basic '):
            auth_info = ClientSecretBasic(endpoint_context).verify(
                request, authorization_info)
            auth_info['method'] = 'client_secret_basic'
        elif authorization_info.startswith('Bearer '):
            auth_info = BearerHeader(endpoint_context).verify(
                request, authorization_info)
            auth_info['method'] = 'bearer_header'
        else:
            raise UnknownOrNoAuthnMethod(authorization_info)

    try:
        client_id = auth_info['client_id']
    except KeyError:
        client_id = ''
        try:
            _token = auth_info['token']
        except KeyError:
            pass
            logger.warning('Unknown client ID')
        else:
            sinfo = endpoint_context.sdb[_token]
            auth_info['client_id'] = sinfo['authn_req']['client_id']
    else:
        try:
            _cinfo = endpoint_context.cdb[client_id]
        except KeyError:
            raise ValueError('Unknown Client ID')
        else:
            if isinstance(_cinfo,str):
                try:
                    _cinfo = endpoint_context.cdb[_cinfo]
                except KeyError:
                    raise ValueError('Unknown Client ID')

            try:
                valid_client_info(_cinfo)
            except KeyError:
                logger.warning('Client registration has timed out')
                raise ValueError('Not valid client')
            else:
                # check that the expected authz method was used
                try:
                    endpoint_context.cdb[client_id]['auth_method'][
                        request.__class__.__name__] = auth_info['method']
                except KeyError:
                    try:
                        endpoint_context.cdb[client_id]['auth_method'] = {
                            request.__class__.__name__: auth_info['method']}
                    except KeyError:
                        pass

    return auth_info
