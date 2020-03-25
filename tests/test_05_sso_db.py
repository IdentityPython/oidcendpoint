import pytest

from oidcendpoint.shelve_db import ShelveDataBase
from oidcendpoint.sso_db import SSODb


class TestSessionDB(object):
    @pytest.fixture(autouse=True)
    def create_sdb(self):
        self.sso_db = SSODb()

    def test_map_sid2uid(self):
        self.sso_db.map_sid2uid("session id 1", "Lizz")
        assert self.sso_db.get_sids_by_uid("Lizz") == ["session id 1"]

    def test_missing_map(self):
        assert self.sso_db.get_sids_by_uid("Lizz") is None

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

        self.sso_db.remove_sid2uid("session id 1", "Lizz")
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
        assert self.sso_db.get_uid_by_sid("session id 1") is None
        assert self.sso_db.get_sids_by_uid("Lizz") is None

    def test_map_sid2sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        assert self.sso_db.get_sids_by_sub("abcdefgh") == ["session id 1"]

    def test_missing_sid2sub_map(self):
        assert self.sso_db.get_sids_by_sub("abcdefgh") is None

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

        self.sso_db.remove_sid2sub("session id 1", "abcdefgh")
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

        self.sso_db.remove_sub("abcdefgh")
        assert self.sso_db.get_sub_by_sid("session id 1") is None
        assert self.sso_db.get_sids_by_sub("abcdefgh") is None
        # have not touched the others
        assert self.sso_db.get_sub_by_sid("session id 2") == "012346789"
        assert self.sso_db.get_sids_by_sub("012346789") == ["session id 2"]

    def test_get_sub_by_uid_same_sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "abcdefgh")

        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")

        res = self.sso_db.get_subs_by_uid("Lizz")

        assert set(res) == {"abcdefgh"}

    def test_get_sub_by_uid_different_sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "012346789")

        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")

        res = self.sso_db.get_subs_by_uid("Lizz")

        assert set(res) == {"abcdefgh", "012346789"}


class TestSessionShelveDB(object):
    @pytest.fixture(autouse=True)
    def create_sdb(self):
        # Create fresh database each time
        _db = ShelveDataBase(filename='shelf', flag='n', writeback=True)
        self.sso_db = SSODb(_db)

    def test_map_sid2uid(self):
        self.sso_db.map_sid2uid("session id 1", "Lizz")
        assert self.sso_db.get_sids_by_uid("Lizz") == ["session id 1"]

    def test_missing_map(self):
        assert self.sso_db.get_sids_by_uid("Lizz") is None

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

        self.sso_db.remove_sid2uid("session id 1", "Lizz")
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
        assert self.sso_db.get_uid_by_sid("session id 1") is None
        assert self.sso_db.get_sids_by_uid("Lizz") is None

    def test_map_sid2sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        assert self.sso_db.get_sids_by_sub("abcdefgh") == ["session id 1"]

    def test_missing_sid2sub_map(self):
        assert self.sso_db.get_sids_by_sub("abcdefgh") is None

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

        self.sso_db.remove_sid2sub("session id 1", "abcdefgh")
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

        self.sso_db.remove_sub("abcdefgh")
        assert self.sso_db.get_sub_by_sid("session id 1") is None
        assert self.sso_db.get_sids_by_sub("abcdefgh") is None
        # have not touched the others
        assert self.sso_db.get_sub_by_sid("session id 2") == "012346789"
        assert self.sso_db.get_sids_by_sub("012346789") == ["session id 2"]

    def test_get_sub_by_uid_same_sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "abcdefgh")

        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")

        res = self.sso_db.get_subs_by_uid("Lizz")

        assert set(res) == {"abcdefgh"}

    def test_get_sub_by_uid_different_sub(self):
        self.sso_db.map_sid2sub("session id 1", "abcdefgh")
        self.sso_db.map_sid2sub("session id 2", "012346789")

        self.sso_db.map_sid2uid("session id 1", "Lizz")
        self.sso_db.map_sid2uid("session id 2", "Lizz")

        res = self.sso_db.get_subs_by_uid("Lizz")

        assert set(res) == {"abcdefgh", "012346789"}
