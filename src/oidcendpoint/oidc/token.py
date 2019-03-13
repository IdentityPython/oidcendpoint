import logging

from cryptojwt.jwe.exception import JWEException
from cryptojwt.jws.exception import NoSuitableSigningKeys

from oidcmsg import oidc
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenRequest
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import RefreshAccessTokenRequest
from oidcmsg.oidc import TokenErrorResponse

from oidcendpoint import sanitize
from oidcendpoint.client_authn import verify_client
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.token_handler import AccessCodeUsed
from oidcendpoint.token_handler import ExpiredToken
from oidcendpoint.userinfo import by_schema
from oidcendpoint.util import new_cookie

logger = logging.getLogger(__name__)


class AccessToken(Endpoint):
    request_cls = oidc.AccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_cls = TokenErrorResponse
    request_format = 'json'
    request_placement = 'body'
    response_format = 'json'
    response_placement = 'body'
    endpoint_name = 'token_endpoint'

    def __init__(self, endpoint_context, **kwargs):
        Endpoint.__init__(self, endpoint_context, **kwargs)
        self.post_parse_request.append(self._post_parse_request)

    def _access_token(self, req, **kwargs):
        _context = self.endpoint_context
        _sdb = _context.sdb
        _log_debug = logger.debug

        if req["grant_type"] != "authorization_code":
            return self.error_cls(error='invalid_request',
                                  error_description='Unknown grant_type')

        try:
            _access_code = req["code"].replace(' ', '+')
        except KeyError:  # Missing code parameter - absolutely fatal
            return self.error_cls(error='invalid_request',
                                  error_description='Missing code')

        # Session might not exist or _access_code malformed
        try:
            _info = _sdb[_access_code]
        except KeyError:
            return self.error_cls(error="invalid_request",
                                  error_description="Code is invalid")

        _authn_req = _info['authn_req']

        # assert that the code is valid
        if _context.sdb.is_session_revoked(_access_code):
            return self.error_cls(error="invalid_request",
                                  error_description="Session is revoked")

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _authn_req:
            if req["redirect_uri"] != _authn_req["redirect_uri"]:
                return self.error_cls(error="invalid_request",
                                      error_description="redirect_uri mismatch")

        _log_debug("All checks OK")

        issue_refresh = False
        if "issue_refresh" in kwargs:
            issue_refresh = kwargs["issue_refresh"]

        # offline_access the default if nothing is specified
        permissions = _info.get('permission', ['offline_access'])

        if 'offline_access' in _authn_req['scope'] and 'offline_access' in permissions:
            issue_refresh = True

        try:
            _info = _sdb.upgrade_to_token(_access_code,
                                          issue_refresh=issue_refresh)
        except AccessCodeUsed as err:
            logger.error("%s" % err)
            # Should revoke the token issued to this access code
            _sdb.revoke_all_tokens(_access_code)
            return self.error_cls(error="access_denied",
                                  error_description="Access Code already used")

        if "openid" in _authn_req["scope"]:
            try:
                _idtoken = _context.idtoken.make(req, _info, _authn_req)
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                resp = TokenErrorResponse(
                    error="invalid_request",
                    error_description="Could not sign/encrypt id_token")
                return resp

            _sdb.update_by_token(_access_code, id_token=_idtoken)
            _info = _sdb[_access_code]

        return by_schema(AccessTokenResponse, **_info)

    def _refresh_access_token(self, req, **kwargs):
        _sdb = self.endpoint_context.sdb

        client_id = str(req['client_id'])

        if req["grant_type"] != "refresh_token":
            return self.error_cls(error='invalid_request',
                                  error_description='Wrong grant_type')

        rtoken = req["refresh_token"]
        try:
            _info = _sdb.refresh_token(rtoken, client_id=client_id)
        except ExpiredToken:
            return self.error_cls(error="invalid_request",
                                  error_description="Refresh token is expired")

        return by_schema(AccessTokenResponse, **_info)

    def client_authentication(self, request, auth=None, **kwargs):
        try:
            auth_info = verify_client(self.endpoint_context, request, auth)
            msg = ''
        except Exception as err:
            msg = "Failed to verify client due to: {}".format(err)
            logger.error(msg)
            return self.error_cls(error="unauthorized_client",
                                  error_description=msg)
        else:
            if 'client_id' not in auth_info:
                logger.error('No client_id, authentication failed')
                return self.error_cls(error="unauthorized_client",
                                      error_description='unknown client')

        return auth_info

    def _post_parse_request(self, request, client_id='', **kwargs):
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param authn: Authentication info, comes from HTTP header
        :returns:
        """

        if 'state' in request:
            try:
                sinfo = self.endpoint_context.sdb[request['code']]
            except KeyError:
                logger.error('Code not present in SessionDB')
                return self.error_cls(error="unauthorized_client")
            else:
                state = sinfo['authn_req']['state']

            if state != request['state']:
                logger.error('State value mismatch')
                return self.error_cls(error="unauthorized_client")

        if "refresh_token" in request:
            request = RefreshAccessTokenRequest(**request.to_dict())

            try:
                keyjar = self.endpoint_context.keyjar
            except AttributeError:
                keyjar = ""

            request.verify(keyjar=keyjar, opponent_id=client_id)

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = client_id

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request

    def process_request(self, request=None, **kwargs):
        """

        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        if isinstance(request, AccessTokenRequest):
            try:
                response_args = self._access_token(request, **kwargs)
            except JWEException as err:
                return self.error_cls(error="invalid_request",
                                      error_description="%s" % err)

        else:
            response_args = self._refresh_access_token(request, **kwargs)

        if isinstance(response_args, ResponseMessage):
            return response_args

        _access_code = request["code"].replace(' ', '+')
        _cookie = new_cookie(self.endpoint_context,
                             sub=self.endpoint_context.sdb[_access_code]['sub'])
        _headers = [('Content-type', 'application/json')]
        resp = {'response_args': response_args, 'http_headers': _headers}
        if _cookie:
            resp['cookie'] = _cookie
        return resp
