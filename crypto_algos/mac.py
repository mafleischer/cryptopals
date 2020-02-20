import types
from crypto_algos.submodules.sha1.sha1 import sha1
from crypto_algos import aes


def sha1MAC(bstr_key: bytes, bstr_clear: bytes) -> bytes:
    """

    :param bstr_key:
    :param bstr_clear:
    :return: sha1 keyed MAC tag
    """
    return sha1(bstr_key + bstr_clear).encode('ascii')