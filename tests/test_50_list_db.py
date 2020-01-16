import os

from oidcendpoint.list_db import ListDB
from oidcendpoint.token_handler import DefaultToken


def full_path(local_file):
    _dirname = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(_dirname, local_file)


def test():
    lst = ListDB("temp")
    lst.append("xyz")
    lst.append("foo")
    lst.append("bar")

    assert "foo" in lst
    lst.close()


def test_blacklist_in_handler():
    password = "The longer the better. Is this close to enough ?"
    grant_expires_in = 600

    code_handler = DefaultToken(password, typ="A", lifetime=grant_expires_in,
                                black_list=ListDB(full_path('code_bl')))

    code_handler.black_list('mamba')

    assert code_handler.is_black_listed("mamba")

    # Close the DBM database
    code_handler.blist.close()

    # reopen
    code_handler.blist = ListDB(full_path('code_bl'))

    # Should still be there
    assert code_handler.is_black_listed("mamba")
