#!/usr/bin/python3

import types
from crypto_algos.helpers import xorBytestrings

def aesCTREditRecoverPlain(ctr_edit_fn: types.FunctionType,
                           *edit_fn_args) -> bytes:
    """
    Recovers the the plain text to a ctr encoded stream by calling the
    CTR edit function on it with and editing the whole plain text.
    The key is then "removed" by xoring the original and the edited
    cipher text leaving the xored original plain text and the newplain
    text
    :param ctr_edit_fn: CTR edit function name
    :param edit_fn_args: the arguments to the function. assumes the cipher
    bytearray is the first
    :return:
    """
    original_cipher = edit_fn_args[0][:]
    newplain = b'X' * len(original_cipher)
    ctr_edit_fn(*edit_fn_args[:-1], newplain)
    plain_xor = xorBytestrings(original_cipher, edit_fn_args[0])
    return xorBytestrings(plain_xor, newplain)