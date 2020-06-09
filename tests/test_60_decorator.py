from abstorage.extension import LabeledAbstractStorage

STORAGE_CONF = {
    'handler': 'abstorage.storages.abfile.AbstractFileSystem',
    'fdir': 'client_db',
    'key_conv': 'abstorage.converter.QPKey',
    'value_conv': 'abstorage.converter.JSON'
}


def test_decorator():
    las = LabeledAbstractStorage(STORAGE_CONF, 'foo')
    las.set('bar', 1234567890)
    nr = las.get('bar')
    assert nr == 1234567890
