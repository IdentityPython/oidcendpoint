import pytest

from oidcendpoint.sso_db import SSODb


class TestSessionDB(object):
    @pytest.fixture(autouse=True)
    def create_sdb(self):
        self.sso_db = SSODb()

    def test_map_sid2uid(self):
        self.sso_db.map_sid2uid("session id 1", "Lizz")
        assert self.sso_db.get_sids_by_uid("Lizz") == ["session id 1"]

    def test_missing_map(self):
        with pytest.raises(KeyError):
            self.sso_db.get_sids_by_uid("Lizz")

    def test_multiple_map_sid2uid(self):
        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")
        assert set(self.sso_db.get_sids_by_uid("Lizz")) == {
            "session id 1",
            "session id 2",
        }

    def test_map_unmap_sid2uid(self):
        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")
        assert set(self.sso_db.get_sids_by_uid("Lizz")) == {
            "session id 1",
            "session id 2",
        }

        self.sso_db.unmap_sid2uid("session id 1", "Lizz")
        assert self.sso_db.get_sids_by_uid("Lizz") == ["session id 2"]

    def test_get_uid_by_sid(self):
        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")

        assert self.sso_db.get_uid_by_sid("session id 1") == "Lizz"
        assert self.sso_db.get_uid_by_sid("session id 2") == "Lizz"

    def test_remove_uid(self):
        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Diana")

        self.sso_db.remove_uid("Lizz")
        assert set(self.sso_db.uid2sid.keys()) == {"Diana"}
        assert set(self.sso_db.uid2sid_rev.keys()) == {"session id 2"}

    def test_map_sid2sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        assert self.sso_db.get_sids_by_sub("abcdefgh") == ["session id 1"]

    def test_missing_sid2sub_map(self):
        with pytest.raises(KeyError):
            self.sso_db.get_sids_by_sub("abcdefgh")

    def test_multiple_map_sid2sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "abcdefgh")
        assert set(self.sso_db.get_sids_by_sub("abcdefgh")) == {
            "session id 1",
            "session id 2",
        }

    def test_map_unmap_sid2sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "abcdefgh")
        assert set(self.sso_db.get_sids_by_sub("abcdefgh")) == {
            "session id 1",
            "session id 2",
        }

        self.sso_db.unmap_sid2sub("session id 1", "abcdefgh")
        assert self.sso_db.get_sids_by_sub("abcdefgh") == ["session id 2"]

    def test_get_sub_by_sid(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "abcdefgh")

        assert set(self.sso_db.get_sids_by_sub("abcdefgh")) == {
            "session id 1",
            "session id 2",
        }

    def test_remove_sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "012346789")

        self.sso_db.remove_sub("012346789")
        assert set(self.sso_db.sub2sid.keys()) == {"abcdefgh"}
        assert set(self.sso_db.sub2sid_rev.keys()) == {"session id 1"}

    def test_get_sub_by_uid_same_sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "abcdefgh")

        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")

        res = self.sso_db.get_sub_by_uid("Lizz")

        assert res == {"abcdefgh"}

    def test_get_sub_by_uid_different_sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "012346789")

        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")

        res = self.sso_db.get_sub_by_uid("Lizz")

        assert res == {"abcdefgh", "012346789"}
