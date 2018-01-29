import logging

from cryptojwt.jwe import JWEException
from cryptojwt.jws import NoSuitableSigningKeys
from oicmsg import oic
from oicmsg.oic import AccessTokenRequest
from oicmsg.oic import AccessTokenResponse
from oicmsg.oic import RefreshAccessTokenRequest
from oicmsg.oic import TokenErrorResponse
from oicsrv.util import make_headers

from oicsrv import sanitize
from oicsrv.endpoint import Endpoint
from oicsrv.id_token import sign_encrypt_id_token
from oicsrv.token_handler import AccessCodeUsed
from oicsrv.token_handler import ExpiredToken
from oicsrv.userinfo import by_schema
from oicsrv.userinfo import userinfo_in_id_token_claims

logger = logging.getLogger(__name__)


class AccessToken(Endpoint):
    request_cls = oic.AccessTokenRequest
    response_cls = oic.AccessTokenResponse
    error_cls = TokenErrorResponse
    request_format = 'json'
    response_format = 'json'
    response_placement = 'body'

    def __init__(self, keyjar):
        Endpoint.__init__(self, keyjar)
        self.pre_construct.append(self._pre_construct)
        self.post_parse_request.append(self._post_parse_request)

    def _pre_construct(self, srv_info, response_args, request, **kwargs):
        _access_code = request["code"].replace(' ', '+')
        _info = srv_info.sdb[_access_code]

        if "openid" in _info["scope"]:
            userinfo = userinfo_in_id_token_claims(srv_info, _info)
            try:
                _idtoken = sign_encrypt_id_token(srv_info, _info,
                                                 str(request["client_id"]),
                                                 user_info=userinfo)
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                return self.error_cls(error="invalid_request",
                                      descr="Could not sign/encrypt id_token")

            srv_info.sdb.update_by_token(_access_code, id_token=_idtoken)
            response_args['id_token'] = _idtoken

        return response_args

    def _access_token(self, srv_info, req, **kwargs):

        _sdb = srv_info.sdb
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

        # assert that the code is valid
        if srv_info.sdb.is_session_revoked(_access_code):
            return self.error_cls(error="invalid_request",
                                  error_description="Session is revoked")

        # If redirect_uri was in the initial authorization request
        # verify that the one given here is the correct one.
        if "redirect_uri" in _info:
            if req["redirect_uri"] != _info["redirect_uri"]:
                return self.error_cls(error="invalid_request",
                                      error_description="redirect_uri mismatch")

        _log_debug("All checks OK")

        issue_refresh = False
        if "issue_refresh" in kwargs:
            issue_refresh = kwargs["issue_refresh"]

        permissions = _info.get('permission', ['offline_access']) or [
            'offline_access']
        if 'offline_access' in _info[
                'scope'] and 'offline_access' in permissions:
            issue_refresh = True

        try:
            _info = _sdb.upgrade_to_token(_access_code,
                                           issue_refresh=issue_refresh)
        except AccessCodeUsed as err:
            logger.error("%s" % err)
            # Should revoke the token issued to this access code
            _sdb.revoke_all_tokens(_access_code)
            return self.error_cls(error="access_denied",
                                  descr="Access Code already used")

        if "openid" in _info["scope"]:
            userinfo = userinfo_in_id_token_claims(srv_info, _info)
            client_info = srv_info.cdb[str(req["client_id"])]
            try:
                _idtoken = sign_encrypt_id_token(srv_info,
                    _info, client_info, sign=True, user_info=userinfo)
            except (JWEException, NoSuitableSigningKeys) as err:
                logger.warning(str(err))
                return self.error_cls(error="invalid_request",
                             erro_description="Could not sign/encrypt id_token")

            _sdb.update_by_token(_access_code, id_token=_idtoken)
            _info = _sdb[_access_code]

        return by_schema(AccessTokenResponse, **_info)

    def _refresh_access_token(self, srv_info, req, **kwargs):
        _sdb = srv_info.sdb

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

    def client_authentication(self, srv_info, request, auth=None, **kwargs):
        try:
            client_id = srv_info.client_authn(srv_info, request, auth)
            msg = ""
        except Exception as err:
            msg = "Failed to verify client due to: {}".format(err)
            logger.error(msg)
            client_id = ""

        if not client_id:
            logger.error('No client_id, authentication failed')
            return self.error_cls(error="unauthorized_client",
                                  error_description=msg)

        return client_id

    def _post_parse_request(self, srv_info, request, client_id='', **kwargs):
        """
        This is where clients come to get their access tokens

        :param request: The request
        :param authn: Authentication info, comes from HTTP header
        :returns:
        """

        if 'state' in request:
            try:
                state = srv_info.sdb[request['code']]['state']
            except KeyError:
                logger.error('Code not present in SessionDB')
                return self.error_cls(error="unauthorized_client")

            if state != request['state']:
                logger.error('State value mismatch')
                return self.error_cls(error="unauthorized_client")

        if "refresh_token" in request:
            request = RefreshAccessTokenRequest(**request.to_dict())

            try:
                keyjar = self.keyjar
            except AttributeError:
                keyjar = ""

            request.verify(keyjar=keyjar, opponent_id=client_id)

        if "client_id" not in request:  # Optional for access token request
            request["client_id"] = client_id

        logger.debug("%s: %s" % (request.__class__.__name__, sanitize(request)))

        return request

    def process_request(self, srv_info, request=None, **kwargs):
        """

        :param srv_info:
        :param request:
        :param kwargs:
        :return: Dictionary with response information
        """
        if isinstance(request, AccessTokenRequest):
            try:
                response_args = self._access_token(srv_info, request, **kwargs)
            except JWEException as err:
                return self.error_cls(error="invalid_request",
                                      erro_description="%s" % err)

        else:
            response_args = self._refresh_access_token(srv_info, request, **kwargs)

        _access_code = request["code"].replace(' ', '+')
        _headers = make_headers(srv_info, srv_info.sdb[_access_code]['user'])
        _headers.append(('Content-type', 'application/json'))
        return {'response_args': response_args, 'http_headers': _headers}
