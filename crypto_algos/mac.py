from crypto_algos.submodules.sha1 import sha1
from crypto_algos import aes


def sha1MAC(bstr_key: bytes, bstr_clear: bytes) -> bytes:
    """

    :param bstr_key:
    :param bstr_clear:
    :return: sha1 keyed MAC tag
    """
    return sha1(bstr_key + bstr_clear).encode('ascii')


def sha1MACTagCipher(bstr_cipher: bytes, bstr_clear: bytes, bstr_key: bytes) -> bytes:
    """

    :param bstr_cipher:
    :param bstr_clear:
    :param bstr_key:
    :return:
    """
    tag = sha1MAC(bstr_key, bstr_clear)
    return bstr_cipher + tag


def sha1MACAuthMsg(bstr_cipher_tag: bytes, bstr_key: bytes, bstr_clear: bytes) -> bool:
    tag = bstr_cipher_tag[-40:]
    if sha1MAC(bstr_key, bstr_clear).encode('ascii') == tag:
        return True
    return False