class InMemoryDataBase(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, key):
        try:
            return self.db[key]
        except KeyError:
            return None

    def delete(self, key):
        del self.db[key]

    def keys(self):
        return self.db.keys()
