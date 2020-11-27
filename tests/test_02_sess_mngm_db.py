# Database is organized in 3 layers. User-session-grant.
import pytest

from oidcendpoint.authn_event import create_authn_event
from oidcendpoint.grant import Grant
from oidcendpoint.grant import Token
from oidcendpoint.session_management import ClientSessionInfo
from oidcendpoint.session_management import Database
from oidcendpoint.session_management import UserSessionInfo
from oidcendpoint.session_management import public_id


class TestDB:
    @pytest.fixture(autouse=True)
    def setup_environment(self):
        self.db = Database()

    def test_user_info(self):
        with pytest.raises(KeyError):
            self.db.get(['diana'])

        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        user_info = self.db.get(['diana'])
        assert user_info["foo"] == "bar"

    def test_client_info(self):
        user_info = UserSessionInfo(foo="bar")
        self.db.set(['diana'], user_info)
        client_info = ClientSessionInfo(sid="abcdef")
        self.db.set(['diana', "client_1"], client_info)

        user_info = self.db.get(['diana'])
        assert user_info['subordinate'] == ['client_1']
        client_info = self.db.get(['diana', "client_1"])
        assert client_info['sid'] == "abcdef"

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
