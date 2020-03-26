import shelve


class ShelveDataBase(object):
    def __init__(self, filename, flag='c', protocol=None, writeback=False):
        self.db = shelve.open(filename=filename, flag=flag, protocol=protocol, writeback=writeback)

    def __contains__(self, key):
        if key in self.db:
            return True
        else:
            return False

    def set(self, key, value):
        self.db[key] = value

    def get(self, key, default=None):
        try:
            return self.db[key]
        except KeyError:
            return default

    def delete(self, key):
        try:
            del self.db[key]
        except KeyError:
            return

    def keys(self):
        return self.db.keys()

    def clear(self):
        self.db.clear()

    def close(self):
        self.db.close()