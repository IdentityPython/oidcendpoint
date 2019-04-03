class LoginHintLookup(object):
    def __init__(self, userinfo=None):
        self.userinfo = userinfo
        self.default_country_code = '46'

    def __call__(self, arg):
        if arg.startswith('tel:'):
            _pnr = arg[4:]
            if _pnr[0] == '+':
                pass
            else:
                _pnr = '+' + self.default_country_code + _pnr[1:]
            return self.userinfo.search(phone_number=_pnr)
