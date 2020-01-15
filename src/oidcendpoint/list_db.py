"""
Persistent storage of a list of values.
"""
import dbm


class ListDB:
    def __init__(self, filename):
        self.db = dbm.open(filename, "c")

    def append(self, val):
        self.db[val] = ""  # value is immaterial since it's never used

    def remove(self, val):
        del self.db[val]

    def __contains__(self, item):
        return item in self.db

    def list(self):
        return list(self.db.keys())

    def close(self):
        self.db.close()
