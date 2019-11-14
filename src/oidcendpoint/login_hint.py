from urllib.parse import urlparse


class LoginHintLookup(object):
    def __init__(self, userinfo=None):
        self.userinfo = userinfo
        self.default_country_code = "46"

    def __call__(self, arg):
        if arg.startswith("tel:"):
            _pnr = arg[4:]
            if _pnr[0] == "+":
                pass
            else:
                _pnr = "+" + self.default_country_code + _pnr[1:]
            return self.userinfo.search(phone_number=_pnr)


class LoginHint2Acrs(object):
    def __init__(self, scheme_map):
        self.scheme_map = scheme_map

    def __call__(self, hint):
        p = urlparse(hint)
        try:
            return self.scheme_map[p.scheme]
        except KeyError:
            return []
