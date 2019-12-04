class InMemoryDataBase(object):
    def __init__(self):
        self.db = {}

    def __contains__(self, key):
        if self.db.get(key):
            return 1

    def set(self, key, value):
        self.db[key] = value

    def get(self, key):
        return self.db.get(key, None)

    def delete(self, key):
        if self.db.get(key):
            del self.db[key]

    def keys(self):
        return self.db.keys()
