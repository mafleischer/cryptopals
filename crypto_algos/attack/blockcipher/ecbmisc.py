from crypto_algos.helpers import stateGenerator
from crypto_algos import aes, misc, challenge_specific
import os
import random


def hasBlockRepetition(bstr):
    """
    Detect block repetition in byte string

    Returns: True if repetition found
            false otherwise
    """

    state_iter = stateGenerator(bstr, 16)
    state_list = [state for state in state_iter]
    for state in state_list:
        if state_list.count(state) > 1:
            return True
    return False

    # is it theoretically possible to have repetition by chance with cbc?

    # maxkey = max(state_counts.keys(), key=(lambda k: state_counts[k]))
    # if state_counts[maxkey] >= threshold:
    #    bstrs_w_highest_state_count[bstr] = state_counts[maxkey]


def isECB(bstr):
    return True if hasBlockRepetition(bstr) else False


def discoverBlocksize(bstr_cipher):
    """
    just alibi function; ideally make this a real checking function
    """
    if len(bstr_cipher) % 16 == 0:
        return 16


def aesRandomEncOracle(bstr_clear, bits=128):
    """
    encrypt input with random key and random appended and prepended bytes

    return: cipher and (for verification) encryption mode as tuple
    """
    blocksize = 16
    key = os.urandom(blocksize)
    numbytes = random.randint(5, 10)
    bytes_prepend = os.urandom(numbytes)
    bytes_append = os.urandom(numbytes)
    bstr_clear = misc.padPKCS7(
        bytes_prepend + bstr_clear + bytes_append, blocksize)

    mode_switch = random.randint(1, 2)
    mode = ""
    if mode_switch == 1:
        mode = 'ecb'
    else:
        mode = 'cbc'

    cipher = b''
    if mode_switch == 1:
        cipher = aes.aesEncrypt(bstr_clear, key, 128, mode=mode, bstr_IV=None)
    else:
        IV = os.urandom(blocksize)
        cipher = aes.aesEncrypt(bstr_clear, key, 128, mode=mode, bstr_IV=IV)
    return (cipher, mode)