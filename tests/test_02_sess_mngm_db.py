# Database is organized in 3 layers. User-session-grant.
import pytest

from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.session import session_key
from oidcendpoint.session.database import Database
from oidcendpoint.session.grant import Grant
from oidcendpoint.session.info import ClientSessionInfo
from oidcendpoint.session.info import UserSessionInfo
from oidcendpoint.session.manager import public_id
from oidcendpoint.session.token import Token


class TestDB:
    @pytest.fixture(autouse=True)
    def setup_environment(self):
        self.db = Database()

    def test_user_info(self):
        with pytest.raises(KeyError):
            self.db.get(['diana'])

        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        stored_user_info = self.db.get(['diana'])
        assert stored_user_info["foo"] == "bar"

    def test_client_info(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(['diana', "client_1"], client_info)

        stored_user_info = self.db.get(['diana'])
        assert stored_user_info['subordinate'] == ['client_1']
        stored_client_info = self.db.get(['diana', "client_1"])
        assert stored_client_info['sid'] == "abcdef"

    def test_client_info_change(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(['diana', "client_1"], client_info)

        user_info = self.db.get(['diana'])
        assert user_info['subordinate'] == ['client_1']
        client_info = self.db.get(['diana', "client_1"])
        assert client_info['sid'] == "abcdef"

        client_info = ClientSessionInfo(sid="0123456")
        self.db.set(['diana', "client_1"], client_info)

        stored_client_info = self.db.get(['diana', "client_1"])
        assert stored_client_info['sid'] == "0123456"

    def test_client_info_add1(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(['diana', "client_1"], client_info)

        # The reference is there but not the value
        del self.db._db[session_key('diana', "client_1")]

        client_info = ClientSessionInfo(sid="0123456")
        self.db.set(['diana', "client_1"], client_info)

        stored_client_info = self.db.get(['diana', "client_1"])
        assert stored_client_info['sid'] == "0123456"

    def test_client_info_add2(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(['diana', "client_1"], client_info)

        # The reference is there but not the value
        del self.db._db[session_key('diana', "client_1")]

        grant = Grant()
        access_code = Token('access_code', value='1234567890')
        grant.issued_token.append(access_code)

        self.db.set(['diana', "client_1", "G1"], grant)
        stored_client_info = self.db.get(['diana', "client_1"])
        assert set(stored_client_info.keys()) == {"subordinate", "revoked", "type"}

        stored_grant_info = self.db.get(['diana', 'client_1', 'G1'])
        assert stored_grant_info.issued_at

    def test_jump_ahead(self):
        grant = Grant()
        access_code = Token('access_code', value='1234567890')
        grant.issued_token.append(access_code)

        self.db.set(['diana', "client_1", "G1"], grant)

        user_info = self.db.get(['diana'])
        assert user_info['subordinate'] == ['client_1']
        client_info = self.db.get(['diana', "client_1"])
        assert client_info['subordinate'] == ["G1"]
        grant_info = self.db.get(['diana', 'client_1', 'G1'])
        assert grant_info.issued_at
        assert len(grant_info.issued_token) == 1
        token = grant_info.issued_token[0]
        assert token.value == '1234567890'
        assert token.type == "access_code"

    def test_replace_grant_info_not_there(self):
        grant = Grant()
        access_code = Token('access_code', value='1234567890')
        grant.issued_token.append(access_code)

        self.db.set(['diana', "client_1", "G1"], grant)

        # The reference is there but not the value
        del self.db._db[session_key('diana', "client_1", "G1")]

        grant = Grant()
        access_code = Token('access_code', value='aaaaaaaaa')
        grant.issued_token.append(access_code)

        self.db.set(['diana', "client_1", "G1"], grant)

        stored_grant_info = self.db.get(['diana', 'client_1', 'G1'])
        assert stored_grant_info.issued_at
        assert len(stored_grant_info.issued_token) == 1
        token = stored_grant_info.issued_token[0]
        assert token.value == 'aaaaaaaaa'


    def test_replace_user_info(self):
        # store user info
        self.db.set(['diana'],
                    UserSessionInfo(authentication_event=create_authn_event('diana')))

        self.db.set(['diana'],
                    UserSessionInfo(
                        authentication_event=create_authn_event('diana', authn_time=111111111)))

        stored_user_info = self.db.get(['diana'])
        assert stored_user_info["authentication_event"]["authn_time"] == 111111111

    def test_add_client_info(self):
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(['diana', "client_1"], client_info)

        stored_client_info = self.db.get(['diana', "client_1"])
        assert stored_client_info['sid'] == "abcdef"

    def test_half_way(self):
        # store user info
        self.db.set(['diana'],
                    UserSessionInfo(authentication_event=create_authn_event('diana')))

        grant = Grant()
        access_code = Token('access_code', value='1234567890')
        grant.issued_token.append(access_code)

        self.db.set(['diana', "client_1", "G1"], grant)

        stored_grant_info = self.db.get(['diana', 'client_1', 'G1'])
        assert stored_grant_info.issued_at
        assert len(stored_grant_info.issued_token) == 1

    def test_step_wise(self):
        salt = "natriumklorid"
        # store user info
        self.db.set(['diana'],
                    UserSessionInfo(authentication_event=create_authn_event('diana')))
        # Client specific information
        self.db.set(['diana', 'client_1'], ClientSessionInfo(sub=public_id(
            'diana', salt)))
        # Grant
        grant = Grant()
        access_code = Token('access_code', value='1234567890')
        grant.issued_token.append(access_code)

        self.db.set(['diana', 'client_1', 'G1'], grant)

    def test_removed(self):
        grant = Grant()
        access_code = Token('access_code', value='1234567890')
        grant.issued_token.append(access_code)

        self.db.set(['diana', "client_1", "G1"], grant)
        self.db.delete(['diana', 'client_1'])
        with pytest.raises(ValueError):
            self.db.get(['diana', "client_1", "G1"])

    def test_client_info_removed(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(['diana', "client_1"], client_info)

        # The reference is there but not the value
        del self.db._db[session_key('diana', "client_1")]

        stored_client_info = self.db.get(['diana', "client_1"])
        assert set(stored_client_info.keys()) == {"subordinate", 'revoked'}

    def test_grant_info(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(['diana', "client_1"], client_info)

        with pytest.raises(ValueError):
            self.db.get(['diana', "client_1", "G1"])

        grant = Grant()
        access_code = Token('access_code', value='1234567890')
        grant.issued_token.append(access_code)

        self.db.set(['diana', "client_1", "G1"], grant)

        # removed value
        del self.db._db[session_key('diana', "client_1", "G1")]

        # should return empty SessionInfo
        stored_grant_info = self.db.get(['diana', "client_1", "G1"])
        assert set(stored_grant_info.keys()) == {"subordinate", 'revoked'}
        assert stored_grant_info["subordinate"] == []
        assert stored_grant_info["revoked"] is False

    def test_delete_non_existent_info(self):
        # Does nothing
        self.db.delete(["diana"])

        user_info = UserSessionInfo(foo="bar")
        user_info.add_subordinate('client')
        self.db.set(['diana'], user_info)

        # again silently does nothing
        self.db.delete(["diana", "client"])

        client_info = ClientSessionInfo(sid="abcdef")
        client_info.add_subordinate('G1')
        self.db.set(['diana', "client_1"], client_info)

        # and finally
        self.db.delete(["diana", "client_1", "G1"])

    def test_delete_user_info(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        self.db.delete(["diana"])
        with pytest.raises(KeyError):
            self.db.get(['diana'])
