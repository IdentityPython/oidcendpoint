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
        self.db = {}
        self.acr2id = {}

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

    def __setitem__(self, key, info):
        """
        Adds a new authentication method.

        :param value: A dictionary with metadata and configuration information
        """
        
        for attr in ['acr', 'method']:
            if attr not in info:
                raise ValueError('Required attribute "{}" missing'.format(attr))
            
        self.db[key] = info
        try:
            self.acr2id[info['acr']].append(key)
        except KeyError:
            self.acr2id[info['acr']] = [key]

    def __delitem__(self, key):
        _acr = self.db[key]['acr']
        del self.db[key]
        self.acr2id[_acr].remove(key)
        if not self.acr2id[_acr]:
            del self.acr2id[_acr]

    def __getitem__(self, key):
        item = self.db[key]
        return item['method'], item['acr']

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
            _ids = self.acr2id[acr]
        except KeyError:
            return []
        else:
            _item = self.db[_ids[0]]
            _level = _item["level"]
            if comparision_type != "better":
                if _item["method"]:
                    res = [(_level, _item["method"], _item["acr"])]
                else:
                    res = []
            else:
                res = []

            for ref in _ids[1:]:
                item = self.db[ref]
                res.append((item["level"], item["method"], item["acr"]))
                if func(_level, item["level"]):
                    _level = item["level"]
            res_other = []
            if comparision_type != "exact":
                for id, _dic in self.db.items():
                    if id in _ids:
                        continue
                    elif func(_level, _dic["level"]):
                        if _dic["method"]:
                            _val = (_dic["level"], _dic["method"], _dic["acr"])
                            if _val not in res:
                                res_other.append(_val)
            res.extend(res_other)
            # sort on level
            res.sort(key=cmp_to_key(self._cmp), reverse=True)

            return [(b, c) for a, b, c in res]

    def get_method(self, cls_name):
        """
        Generator that returns all registered authenticators based on a
        specific authentication class.

        :param acr: Authentication Class
        :return: generator
        """
        for id, spec in self.db.items():
            if spec["method"].__class__.__name__ == cls_name:
                yield spec["method"]

    def get_method_by_id(self, id):
        return self[id]

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

    def getAcrValuesString(self):
        acr_values = None
        for item in self.db.values():
            if acr_values is None:
                acr_values = item["acr"]
            else:
                acr_values += " " + item["acr"]
        return acr_values

    def __iter__(self):
        for item in self.db.values():
            yield item["method"]
        raise StopIteration

    def __len__(self):
        return len(self.db.keys())

    def pick_by_path(self, path):
        for key, item in self.db.items():
            _method = item['method']
            try:
                _path = _method.action
            except AttributeError:
                continue
            else:
                if _path == path:
                    return _method
        raise KeyError('No authn method at that path')

    def default(self):
        if len(self.db) >= 1:
            item = list(self.db.values())[0]
            return item['method'], item['acr']
        else:
            return None


def pick_auth(endpoint_context, areq, comparision_type=""):
    """
    Pick authentication method

    :param areq: AuthorizationRequest instance
    :param comparision_type: How to pick the authentication method
    :return: An authentication method and its authn class ref
    """
    if comparision_type == "any":
        return endpoint_context.authn_broker.default()

    try:
        if len(endpoint_context.authn_broker) == 1:
            return endpoint_context.authn_broker.default()
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
                    item = res[0]
                    return item['method'], item['acr']
        else:  # same as any
            try:
                acrs = areq["claims"]["id_token"]["acr"]["values"]
            except KeyError:
                return endpoint_context.authn_broker.default()
            else:
                for acr in acrs:
                    res = endpoint_context.authn_broker.pick(acr, comparision_type)
                    logger.debug("Picked AuthN broker for ACR %s: %s" % (
                        str(acr), str(res)))
                    if res:
                        # Return the best guess by pick.
                        item = res[0]
                        return item['method'], item['acr']

    except KeyError as exc:
        logger.debug(
            "An error occured while picking the authN broker: %s" % str(exc))

    # return the best I have
    return None, None
