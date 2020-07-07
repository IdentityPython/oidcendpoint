from oidcmsg.storage.extension import LabeledAbstractStorage

STORAGE_CONF = {
    "handler": "oidcmsg.storage.abfile.AbstractFileSystem",
    "fdir": "client_db",
    "key_conv": "oidcmsg.storage.converter.QPKey",
    "value_conv": "oidcmsg.storage.converter.JSON",
}


def test_decorator():
    las = LabeledAbstractStorage(STORAGE_CONF, "foo")
    las.set("bar", 1234567890)
    nr = las.get("bar")
    assert nr == 1234567890
