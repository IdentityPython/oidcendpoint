import logging

logger = logging.getLogger(__name__)


class InMemoryDataBase(object):
    def __init__(self):
        self.db = {}

    def __contains__(self, key):
        if self.db.get(key):
            return 1

    def __getitem__(self, key):
        return self.db.get(key, None)

    def __setitem__(self, key, value):
        self.db[key] = value

    def __delitem__(self, key):
        del self.db[key]

    def set(self, key, value):
        self.db[key] = value

    def get(self, key, default=None):
        return self.db.get(key, default)

    def delete(self, key):
        if self.db.get(key):
            del self.db[key]

    def keys(self):
        return self.db.keys()

    def close(self):
        pass

    def clear(self):
        self.db = {}
