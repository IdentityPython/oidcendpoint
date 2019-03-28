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

    def _pick_by_class_ref(self, acr):
        try:
            _ids = self.acr2id[acr]
        except KeyError:
            return []
        else:
            return [self.db[_i] for _i in _ids]

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

    def pick(self, acr=None):
        """
        Given the authentication context find zero or more authn methods
        that could be used.

        :param acr: The authentication class reference requested
        :return: An URL
        """

        if acr is None:
            # Anything else doesn't make sense
            return self.db.values()
        else:
            return self._pick_by_class_ref(acr)

    @staticmethod
    def match(requested, provided):
        if requested == provided:
            return True
        else:
            return False

    def get_acr_value_string(self):
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


def pick_auth(endpoint_context, areq):
    """
    Pick authentication method

    :param areq: AuthorizationRequest instance
    :return: An authentication method and its authn class ref
    """

    try:
        if len(endpoint_context.authn_broker) == 1:
            return endpoint_context.authn_broker.default()
        elif "acr_values" in areq:
            if not isinstance(areq["acr_values"], list):
                areq["acr_values"] = [areq["acr_values"]]
            acrs = areq["acr_values"]
        else:  # same as any
            try:
                acrs = areq["claims"]["id_token"]["acr"]["values"]
            except KeyError:
                return endpoint_context.authn_broker.default()

        for acr in acrs:
            res = endpoint_context.authn_broker.pick(acr)
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
