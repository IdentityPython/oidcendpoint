class OicSrvError(Exception):
    pass


class InvalidRedirectURIError(OicSrvError):
    pass


class InvalidSectorIdentifier(OicSrvError):
    pass


class ConfigurationError(OicSrvError):
    pass


class NoSuchAuthentication(OicSrvError):
    pass


class TamperAllert(OicSrvError):
    pass


class ToOld(OicSrvError):
    pass


class FailedAuthentication(OicSrvError):
    pass


class InstantiationError(OicSrvError):
    pass


class ImproperlyConfigured(OicSrvError):
    pass


class NotForMe(OicSrvError):
    pass


class UnknownAssertionType(OicSrvError):
    pass


class RedirectURIError(OicSrvError):
    pass


class UnknownClient(OicSrvError):
    pass


class UnAuthorizedClient(OicSrvError):
    pass