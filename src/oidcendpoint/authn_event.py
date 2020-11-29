from oidcmsg.message import SINGLE_OPTIONAL_INT
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import Message
from oidcmsg.time_util import time_sans_frac

DEFAULT_AUTHN_EXPIRES_IN = 3600


class AuthnEvent(Message):
    c_param = {
        "uid": SINGLE_REQUIRED_STRING,
        # "salt": SINGLE_REQUIRED_STRING,
        "authn_info": SINGLE_REQUIRED_STRING,
        "authn_time": SINGLE_OPTIONAL_INT,
        "valid_until": SINGLE_OPTIONAL_INT,
    }

    def is_valid(self, now=0):
        if now:
            return self["valid_until"] > now
        else:
            return self["valid_until"] > time_sans_frac()

    def expires_in(self):
        return self["valid_until"] - time_sans_frac()


def create_authn_event(uid, authn_info=None, authn_time: int = 0,
                       valid_until: int = 0, expires_in: int = 0, **kwargs):
    """

    :param authn_time:
    :param uid:
    :param authn_info:
    :param valid_until:
    :param expires_in:
    :param kwargs:
    :return:
    """

    args = {"uid": uid, "authn_info": authn_info}

    if authn_time:
        args["authn_time"] = authn_time
    else:
        _ts = kwargs.get("timestamp")
        if _ts:
            args["authn_time"] = _ts
        else:
            args["authn_time"] = time_sans_frac()

    if valid_until:
        args["valid_until"] = valid_until
    else:
        if expires_in:
            args["valid_until"] = args["authn_time"] + expires_in
        else:
            args["valid_until"] = args["authn_time"] + DEFAULT_AUTHN_EXPIRES_IN

    return AuthnEvent(**args)
