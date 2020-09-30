from oidcmsg.storage.init import storage_factory

STORAGE_CONF = {
    "handler": "oidcmsg.storage.abfile.LabeledAbstractFileSystem",
    "fdir": "client_db",
    "key_conv": "oidcmsg.storage.converter.QPKey",
    "value_conv": "oidcmsg.storage.converter.JSON",
    "label": 'foo'
}


def test_decorator():
    las = storage_factory(STORAGE_CONF)
    las["bar"] = 1234567890
    nr = las.get("bar")
    assert nr == 1234567890
