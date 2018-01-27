from oicsrv.id_token import id_token_payload


def test_id_token_payload_0():
    #session, loa="2", alg="RS256", code=None, access_token=None,
    # user_info=None, auth_time=0, lifetime=300, extra_claims=None
    session_info = {'sub': '1234567890'}

    info = id_token_payload(session_info)
    assert info['payload'] == {'acr': '2', 'sub': '1234567890'}
    assert info['lifetime'] == 300


def test_id_token_payload_1():
    session_info = {'nonce': 'nonce', 'sub': '1234567890'}

    info = id_token_payload(session_info)
    assert info['payload'] == {'acr': '2', 'nonce': 'nonce',
                               'sub': '1234567890'}
    assert info['lifetime'] == 300


def test_id_token_payload_with_code():
    session_info = {'nonce': 'nonce', 'sub': '1234567890'}

    info = id_token_payload(session_info, code='ABCDEFGHIJKLMNOP')
    assert info['payload'] == {'acr': '2', 'nonce': 'nonce',
                               'c_hash': '5-i4nCch0pDMX1VCVJHs1g',
                               'sub': '1234567890'}
    assert info['lifetime'] == 300


def test_id_token_payload_with_access_token():
    session_info = {'nonce': 'nonce', 'sub': '1234567890'}

    info = id_token_payload(session_info, access_token='012ABCDEFGHIJKLMNOP')
    assert info['payload'] == {'acr': '2', 'nonce': 'nonce',
                               'at_hash': 'bKkyhbn1CC8IMdavzOV-Qg',
                               'sub': '1234567890'}
    assert info['lifetime'] == 300


def test_id_token_payload_with_code_and_access_token():
    #session, loa="2", alg="RS256", code=None, access_token=None,
    # user_info=None, auth_time=0, lifetime=300, extra_claims=None
    session_info = {'nonce': 'nonce', 'sub': '1234567890'}

    info = id_token_payload(session_info, access_token='012ABCDEFGHIJKLMNOP',
                            code='ABCDEFGHIJKLMNOP')
    assert info['payload'] == {'acr': '2', 'nonce': 'nonce',
                               'at_hash': 'bKkyhbn1CC8IMdavzOV-Qg',
                               'c_hash': '5-i4nCch0pDMX1VCVJHs1g',
                               'sub': '1234567890'}
    assert info['lifetime'] == 300


def test_id_token_payload_with_userinfo():
    #session, loa="2", alg="RS256", code=None, access_token=None,
    # user_info=None, auth_time=0, lifetime=300, extra_claims=None
    session_info = {'nonce': 'nonce', 'sub': '1234567890'}

    info = id_token_payload(session_info, user_info={'given_name':'Diana'})
    assert info['payload'] == {'acr': '2', 'nonce': 'nonce',
                               'given_name':'Diana', 'sub': '1234567890'}
    assert info['lifetime'] == 300


def test_id_token_payload_many_0():
    #session, loa="2", alg="RS256", code=None, access_token=None,
    # user_info=None, auth_time=0, lifetime=300, extra_claims=None
    session_info = {'nonce': 'nonce', 'sub': '1234567890'}

    info = id_token_payload(session_info, user_info={'given_name':'Diana'},
                            access_token='012ABCDEFGHIJKLMNOP',
                            code='ABCDEFGHIJKLMNOP')
    assert info['payload'] == {'acr': '2', 'nonce': 'nonce',
                               'given_name':'Diana',
                               'at_hash': 'bKkyhbn1CC8IMdavzOV-Qg',
                               'c_hash': '5-i4nCch0pDMX1VCVJHs1g',
                               'sub': '1234567890'}
    assert info['lifetime'] == 300

# sign_encrypt_id_token(srv_info, session_info, client_info, code=None,
#                           access_token=None, user_info=None, sign=True,
#                           encrypt=False):
