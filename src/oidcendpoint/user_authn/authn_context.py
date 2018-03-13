import logging
from functools import cmp_to_key

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

SAML_AC = 'urn:oasis:names:tc:SAML:2.0:ac:classes'
UNSPECIFIED = "{}:unspecified".format(SAML_AC)
INTERNETPROTOCOLPASSWORD = '{}:InternetProtocolPassword'.format(SAML_AC)
MOBILETWOFACTORCONTRACT = '{}:MobileTwoFactorContract'.format(SAML_AC)
PASSWORDPROTECTEDTRANSPORT = '{}:PasswordProtectedTransport'.format(SAML_AC)
PASSWORD = '{}:Password'.format(SAML_AC)
TLSCLIENT = '{}:TLSClient'.format(SAML_AC)
TIMESYNCTOKEN = "{}:TimeSyncToken".format(SAML_AC)

CMP_TYPE = ['exact', 'minimum', 'maximum', 'better']


class AuthnBroker(object):
    def __init__(self):
        self.db = {"info": {}, "key": {}}
        self.next = 0

    @staticmethod
    def exact(a, b):
        return a == b

    @staticmethod
    def minimum(a, b):
        return b >= a

    @staticmethod
    def maximum(a, b):
        return b <= a

    @staticmethod
    def better(a, b):
        return b > a

    def add(self, acr, method, level=0, authn_authority=""):
        """
        Adds a new authentication method.
        Assumes not more than one authentication method per type.

        :param acr: Add to what the authentication endpoint offers for this acr
        :param method: A identifier of the authentication method.
        :param level: security level, positive integers, 0 is lowest
        :param authn_authority: Who is authoritative for the authentication
        :return:
        """

        _info = {
            "ref": acr,
            "method": method,
            "level": level,
            "authn_auth": authn_authority
        }

        self.next += 1
        _ref = str(self.next)
        self.db["info"][_ref] = _info
        try:
            self.db["key"][acr].append(_ref)
        except KeyError:
            self.db["key"][acr] = [_ref]

    def remove(self, acr, method=None, level=0, authn_authority=""):
        try:
            _refs = self.db["key"][acr]
        except KeyError:
            return
        else:
            _remain = []
            for _ref in _refs:
                item = self.db["info"][_ref]
                if method and method != item["method"]:
                    _remain.append(_ref)
                if level and level != item["level"]:
                    _remain.append(_ref)
                if authn_authority and authn_authority != item[
                        "authn_authority"]:
                    _remain.append(_ref)
            if _remain:
                self.db[acr] = _remain

    @staticmethod
    def _cmp(item0, item1):
        v0 = item0[0]
        v1 = item1[0]
        if v0 > v1:
            return 1
        elif v0 == v1:
            return 0
        else:
            return -1

    def _pick_by_class_ref(self, acr, comparision_type="exact"):
        func = getattr(self, comparision_type)
        try:
            _refs = self.db["key"][acr]
        except KeyError:
            return []
        else:
            _info = self.db["info"]
            _item = _info[_refs[0]]
            _level = _item["level"]
            if comparision_type != "better":
                if _item["method"]:
                    res = [(_level, _item["method"], _item["ref"])]
                else:
                    res = []
            else:
                res = []

            for ref in _refs[1:]:
                item = _info[ref]
                res.append((item["level"], item["method"], item["ref"]))
                if func(_level, item["level"]):
                    _level = item["level"]
            res_other = []
            if comparision_type != "exact":
                for ref, _dic in _info.items():
                    if ref in _refs:
                        continue
                    elif func(_level, _dic["level"]):
                        if _dic["method"]:
                            _val = (_dic["level"], _dic["method"], _dic["ref"])
                            if _val not in res:
                                res_other.append(_val)
            res.extend(res_other)
            # sort on level
            res.sort(key=cmp_to_key(self._cmp), reverse=True)

            return [(b, c) for a, b, c in res]

    def get_method(self, name):
        for key, item in self.db["info"].items():
            if item["method"].__class__.__name__ == name:
                return item["method"]
        raise KeyError("No method by that name")

    def pick(self, acr=None, comparision_type="minimum"):
        """
        Given the authentication context find zero or more places where
        the user could be sent next. Ordered according to security level.

        :param acr: The authentication class reference requested
        :param comparision_type: If the caller wants exact, at a minimum,
            ... this level
        :return: An URL
        """

        if not comparision_type:
            comparision_type = "minimum"

        if acr is None:
            # Anything else doesn't make sense
            return self._pick_by_class_ref(UNSPECIFIED, "minimum")
        else:
            return self._pick_by_class_ref(acr, comparision_type)

    @staticmethod
    def match(requested, provided):
        if requested == provided:
            return True
        else:
            return False

    def __getitem__(self, item):
        i = 0
        for key, info in self.db["info"].items():
            if i == item:
                return info["method"], info["ref"]
            i += 1

        raise IndexError()

    def getAcrValuesString(self):
        acr_values = None
        for item in self.db["info"].values():
            if acr_values is None:
                acr_values = item["ref"]
            else:
                acr_values += " " + item["ref"]
        return acr_values

    def __iter__(self):
        for item in self.db["info"].values():
            yield item["method"]
        raise StopIteration

    def __len__(self):
        return len(self.db["info"].keys())


def pick_auth(endpoint_context, areq, comparision_type=""):
    """

    :param areq: AuthorizationRequest instance
    :param comparision_type: How to pick the authentication method
    :return: An authentication method and its authn class ref
    """
    if comparision_type == "any":
        return endpoint_context.authn_broker[0]

    try:
        if len(endpoint_context.authn_broker) == 1:
            return endpoint_context.authn_broker[0]
        elif "acr_values" in areq:
            if not comparision_type:
                comparision_type = "exact"

            if not isinstance(areq["acr_values"], list):
                areq["acr_values"] = [areq["acr_values"]]

            for acr in areq["acr_values"]:
                res = endpoint_context.authn_broker.pick(acr, comparision_type)
                logger.debug("Picked AuthN broker for ACR %s: %s" % (
                    str(acr), str(res)))
                if res:
                    # Return the best guess by pick.
                    return res[0]
        else:  # same as any
            try:
                acrs = areq["claims"]["id_token"]["acr"]["values"]
            except KeyError:
                return endpoint_context.authn_broker[0]
            else:
                for acr in acrs:
                    res = endpoint_context.authn_broker.pick(acr, comparision_type)
                    logger.debug("Picked AuthN broker for ACR %s: %s" % (
                        str(acr), str(res)))
                    if res:
                        # Return the best guess by pick.
                        return res[0]

    except KeyError as exc:
        logger.debug(
            "An error occured while picking the authN broker: %s" % str(
                exc))

    # return the best I have
    return None, None
