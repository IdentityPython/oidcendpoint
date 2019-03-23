import json
import logging
from urllib.parse import urlencode

from cryptojwt import as_unicode
from cryptojwt import b64d
from cryptojwt.jws.exception import JWSException
from cryptojwt.jws.jws import factory
from cryptojwt.jws.utils import alg2keytype
from cryptojwt.jwt import JWT
from cryptojwt.utils import as_bytes
from oidcmsg.exception import InvalidRequest
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import verified_claim_name
from oidcmsg.oidc.session import BACK_CHANNEL_LOGOUT_EVENT
from oidcmsg.oidc.session import EndSessionRequest

from oidcendpoint import URL_ENCODED
from oidcendpoint.client_authn import UnknownOrNoAuthnMethod
from oidcendpoint.cookie import append_cookie
from oidcendpoint.endpoint import Endpoint
from oidcendpoint.oidc.authorization import join_query
from oidcendpoint.oidc.authorization import verify_uri
from oidcendpoint.util import OAUTH2_NOCACHE_HEADERS

logger = logging.getLogger(__name__)


def do_front_channel_logout_iframe(cinfo, iss, sid):
    """

    :param cinfo: Client info
    :param iss: Issuer ID
    :param sid: Session ID
    :return: IFrame
    """
    try:
        frontchannel_logout_uri = cinfo['frontchannel_logout_uri']
    except KeyError:
        return None

    try:
        flsr = cinfo['frontchannel_logout_session_required']
    except KeyError:
        flsr = False

    if flsr:
        _query = urlencode({'iss': iss, 'sid': sid})
        _iframe = '<iframe src="{}?{}">'.format(frontchannel_logout_uri,
                                                _query)
    else:
        _iframe = '<iframe src="{}">'.format(frontchannel_logout_uri)

    return _iframe


class Session(Endpoint):
    request_cls = EndSessionRequest
    response_cls = Message
    request_format = 'urlencoded'
    response_format = 'urlencoded'
    response_placement = 'url'
    endpoint_name = 'end_session_endpoint'

    def do_response(self, response_args=None, request=None, error='', **kwargs):
        """
        Gather response information

        :param response_args: Things that should be in the response
        :param request: The original request
        :param error: Possible error message
        :param kwargs: Extra keyword arguments
        :return: A dictionary with 2 keys 'response' and ' http_headers'
        """
        if error:
            return Endpoint.do_response(self, response_args, request,
                                        error, **kwargs)

        http_headers = [('Content-type', URL_ENCODED)]
        http_headers.extend(OAUTH2_NOCACHE_HEADERS)

        _resp = '{}?{}'.format(self.kwargs['logout_uri'],
                               urlencode(kwargs))

        return {'response': _resp, 'http_headers': http_headers}

    def do_back_channel_logout(self, cinfo, sub, sid):
        """

        :param cinfo: Client information
        :param sub: Subject identifier
        :param sid: The Issuer ID
        :return: Tuple with logout URI and signed logout token
        """

        _cntx = self.endpoint_context

        try:
            back_channel_logout_uri = cinfo['backchannel_logout_uri']
        except KeyError:
            return None

        # always include sub and sid so I don't check for
        # backchannel_logout_session_required

        payload = {
            'sub': sub, 'sid': sid,
            'events': {BACK_CHANNEL_LOGOUT_EVENT: {}}
        }

        try:
            alg = cinfo['id_token_signed_response_alg']
        except KeyError:
            alg = _cntx.provider_info['id_token_signing_alg_values_supported'][0]

        _jws = JWT(_cntx.keyjar, iss=_cntx.issuer, lifetime=86400, sign_alg=alg)
        _jws.with_jti = True
        sjwt = _jws.pack(payload=payload, recv=cinfo["client_id"])

        return back_channel_logout_uri, sjwt

    def clean_sessions(self, usids):
        # Clean out all sessions
        _sdb = self.endpoint_context.sdb
        _sso_db = self.endpoint_context.sdb.sso_db
        for sid in usids:
            _state = _sdb[sid]['authn_req']['state']
            del _sdb[sid]
            _sdb.delete_kv2sid('state', _state)
            _sso_db.remove_session_id(sid)

    def logout_all_clients(self, sid, client_id):
        _sdb = self.endpoint_context.sdb
        _sso_db = self.endpoint_context.sdb.sso_db

        # Find all RPs this user has logged it from
        uid = _sso_db.get_uid_by_sid(sid)
        _client_sid = {}
        usids = _sso_db.get_sids_by_uid(uid)
        for usid in usids:
            _client_sid[_sdb[usid]['authn_req']['client_id']] = usid

        # Front-/Backchannel logout ?
        _cdb = self.endpoint_context.cdb
        _iss = self.endpoint_context.issuer
        bc_logouts = {}
        fc_iframes = {}
        for _cid, _csid in _client_sid.items():
            if 'backchannel_logout_uri' in _cdb[_cid]:
                _sub = _sso_db.get_sub_by_sid(_csid)
                _spec = self.do_back_channel_logout(
                    _cdb[_cid], _sub, _csid)
                if _spec:
                    bc_logouts[_cid] = _spec
            elif 'frontchannel_logout_uri' in _cdb[_cid]:
                # Construct an IFrame
                _spec = do_front_channel_logout_iframe(_cdb[_cid], _iss, _csid)
                if _spec:
                    fc_iframes[_cid] = _spec

        self.clean_sessions(usids)

        res = {}
        if bc_logouts:
            res['blu'] = bc_logouts
        if fc_iframes:
            res['flu'] = fc_iframes
        return res

    def unpack_signed_jwt(self, sjwt, sig_alg=''):
        _jwt = factory(sjwt)
        if _jwt:
            if sig_alg:
                alg = sig_alg
            else:
                alg = self.kwargs['signing_alg']

            sign_keys = self.endpoint_context.keyjar.get_signing_key(
                alg2keytype(alg))
            _info = _jwt.verify_compact(keys=sign_keys, sigalg=alg)
            return _info
        else:
            raise ValueError('Not a signed JWT')

    def logout_from_client(self, sid, client_id):
        _cdb = self.endpoint_context.cdb
        _sso_db = self.endpoint_context.sdb.sso_db

        # Kill the session
        _sdb = self.endpoint_context.sdb
        _sdb.revoke_session(sid=sid)

        res = {}
        if 'backchannel_logout_uri' in _cdb[client_id]:
            _sub = _sso_db.get_sub_by_sid(sid)
            _spec = self.do_back_channel_logout(_cdb[client_id], _sub, sid)
            if _spec:
                res['blu'] = {client_id: _spec}
        elif 'frontchannel_logout_uri' in _cdb[client_id]:
            # Construct an IFrame
            _spec = do_front_channel_logout_iframe(
                _cdb[client_id], self.endpoint_context.issuer, sid)
            if _spec:
                res['flu'] = {client_id: _spec}

        self.clean_sessions([sid])
        return res

    def process_request(self, request=None, cookie=None, **kwargs):
        """
        Perform user logout

        :param request:
        :param cookie:
        :param kwargs:
        :return:
        """
        _cntx = self.endpoint_context
        _sdb = _cntx.sdb

        _cookie_name = self.endpoint_context.cookie_name['session']
        try:
            part = self.endpoint_context.cookie_dealer.get_cookie_value(
                cookie, cookie_name=_cookie_name)
        except IndexError:
            raise InvalidRequest('Cookie error')
        except KeyError:
            part = None

        if part:
            # value is a base64 encoded JSON document
            _cookie_info = json.loads(as_unicode(b64d(as_bytes(part[0]))))
            logger.debug('Cookie info: {}'.format(_cookie_info))
            _sid = _cookie_info['sid']
        else:
            logger.debug('No relevant cookie')
            _sid = ''
            _cookie_info = {}

        if 'id_token_hint' in request:
            logger.debug(
                'ID token hint: {}'.format(
                    request[verified_claim_name("id_token_hint")]))

            auds = request[verified_claim_name("id_token_hint")]['aud']
            _ith_sid = ''
            _sids = _sdb.sso_db.get_sids_by_sub(
                request[verified_claim_name("id_token_hint")]['sub'])

            if _sids is None:
                raise ValueError('Unknown subject identifier')

            for _isid in _sids:
                if _sdb[_isid]['authn_req']['client_id'] in auds:
                    _ith_sid = _isid
                    break

            if not _ith_sid:
                raise ValueError('Unknown subject')

            if _sid:
                if _ith_sid != _sid:  # someone's messing with me
                    raise ValueError('Wrong ID Token hint')
            else:
                _sid = _ith_sid
        else:
            auds = []

        try:
            session = _sdb[_sid]
        except KeyError:
            raise ValueError("Can't find any corresponding session")

        client_id = session['authn_req']['client_id']
        # Does this match what's in the cookie ?
        if _cookie_info:
            if client_id != _cookie_info['client_id']:
                logger.warning(
                    'Client ID in authz request and in cookie does not match')
                raise ValueError("Wrong Client")

        if auds:
            if client_id not in auds:
                raise ValueError('Incorrect ID Token hint')

        _cinfo = _cntx.cdb[client_id]

        # verify that the post_logout_redirect_uri if present are among the ones
        # registered

        try:
            _uri = request['post_logout_redirect_uri']
        except KeyError:
            _uri = join_query(*_cinfo['post_logout_redirect_uris'][0])
        else:
            verify_uri(_cntx, request, 'post_logout_redirect_uri',
                       client_id=client_id)

        payload = {
            'sid': _sid, 'client_id': client_id,
            'user': session['authn_event']['uid']
        }

        # redirect user to OP logout verification page
        if 'state' in request:
            _uri = '{}?{}'.format(_uri, urlencode({'state': request['state']}))
            payload['state'] = request['state']

        payload['redirect_uri'] = _uri

        logger.debug('JWS payload: {}'.format(payload))
        # From me to me
        _jws = JWT(_cntx.keyjar, iss=_cntx.issuer, lifetime=86400,
                   sign_alg=self.kwargs['signing_alg'])
        sjwt = _jws.pack(payload=payload, recv=_cntx.issuer)

        location = '{}?{}'.format(self.kwargs['logout_verify_url'],
                                  urlencode({'sjwt': sjwt}))
        return {'redirect_location': location}

    def parse_request(self, request, auth=None, **kwargs):
        """

        :param request:
        :param auth:
        :param kwargs:
        :return:
        """

        if not request:
            request = {}

        # Verify that the client is allowed to do this
        try:
            auth_info = self.client_authentication(request, auth, **kwargs)
        except UnknownOrNoAuthnMethod:
            pass
        else:
            if isinstance(auth_info, ResponseMessage):
                return auth_info
            else:
                request['client_id'] = auth_info['client_id']
                request['access_token'] = auth_info['token']

        if isinstance(request, dict):
            request = self.request_cls(**request)
            if not request.verify(keyjar=self.endpoint_context.keyjar,
                                  sigalg=''):
                raise InvalidRequest("Request didn't verify")
            # id_token_signing_alg_values_supported
            try:
                _ith = request[verified_claim_name("id_token_hint")]
            except KeyError:
                pass
            else:
                if _ith.jws_header['alg'] not in \
                        self.endpoint_context.provider_info[
                            'id_token_signing_alg_values_supported']:
                    raise JWSException('Unsupported signing algorithm')

        return request

    def do_verified_logout(self, sid, client_id, alla=False, **kwargs):
        if alla:
            _res = self.logout_all_clients(sid=sid, client_id=client_id)
        else:
            _res = self.logout_from_client(sid=sid, client_id=client_id)

        try:
            bcl = _res['blu']
        except KeyError:
            pass
        else:
            # take care of Back channel logout first
            for _cid, spec in bcl.items():
                _url, sjwt = spec
                logger.info('logging out from {} at {}'.format(_cid, _url))

                res = self.endpoint_context.httpc.post(
                    _url, data="logout_token={}".format(sjwt),
                    verify=self.endpoint_context.verify_ssl)

                if res.status_code < 300:
                    logger.info('Logged out from {}'.format(_cid))
                elif res.status_code >= 400:
                    logger.info('failed to logout from {}'.format(_cid))

        try:
            return _res['flu'].values()
        except KeyError:
            return []

    def kill_cookies(self):
        _ec = self.endpoint_context
        _dealer = _ec.cookie_dealer
        _kakor = append_cookie(
            _dealer.create_cookie(
                'none', typ="session", ttl=0,
                cookie_name=_ec.cookie_name['session_management']),
            _dealer.create_cookie(
                'none', typ="session", ttl=0,
                cookie_name=_ec.cookie_name['session']))

        return _kakor
