import logging

from oidcendpoint.id_token import sign_encrypt_id_token
from oidcendpoint.userinfo import collect_user_info, userinfo_in_id_token_claims

logger = logging.getLogger(__name__)


def make_idtoken(endpoint, req, sess_info, authn_req=None, user_claims=False,
                 **kwargs):
    _context = endpoint.endpoint_context
    _sdb = _context.sdb

    if authn_req:
        _cid = authn_req['client_id']
    else:
        _cid = req['client_id']

    _cinfo = _context.cdb[_cid]
    userinfo = userinfo_in_id_token_claims(_context, sess_info)

    if user_claims:
        info = collect_user_info(_context, sess_info)
        if userinfo is None:
            userinfo = info
        else:
            userinfo.update(info)

    try:
        _client_id = req['client_id']
    except KeyError:
        if authn_req:
            _client_id = authn_req['client_id']
        else:
            raise ValueError('Expected authn request information')

    try:
        req_sid = _cinfo["frontchannel_logout_session_required"]
    except KeyError:
        try:
            req_sid = _cinfo["backchannel_logout_session_required"]
        except KeyError:
            req_sid = False

    if req_sid:
        xargs = {
            'sid': _context.sdb.get_sid_by_sub_and_client_id(
                sess_info['sub'], _client_id)
        }
    else:
        xargs = {}

    return sign_encrypt_id_token(_context, sess_info, _client_id,
                                 sign=True, user_info=userinfo,
                                 extra_claims=xargs, **kwargs)
