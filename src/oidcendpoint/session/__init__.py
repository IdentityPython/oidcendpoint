from typing import List


def session_key(*args) -> str:
    return ';;'.join(args)


def unpack_session_key(key: str) -> List[str]:
    return key.split(';;')


class Revoked(Exception):
    pass


class MintingNotAllowed(Exception):
    pass
