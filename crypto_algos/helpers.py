import numpy as np
from crypto_algos.exceptions import ParamClashError, ParamValueError

def check_chunk(bstr):
    # check state len
    if len(bstr) != 16:
        print("Invalid Chunk length!")
        exit(1)


def rotateList(l, num, direction):
    """
    Rotate list by num steps. direction ist r for right and l for left.
    """
    if direction not in ('l', 'r'):
        print("rotateList: direction must be 'l' or 'r'")
        exit(1)
    # cast to list: to make numpy one dim. arrays lists.
    # Because e.g. numpy array of len 0 (shape (0,)) can't be concatenated
    # to longer length arrays
    if direction == 'l':
        return list(l[num:]) + list(l[0:num])
    else:
        return list(l[-num:]) + list(l[0:-num])


def stateGenerator(bstr_msg: bytes, length: int, modis0: bool = True) -> bytes:
    """
    takes the whole length of the message as a byte
    string and returns blocks of it as byte string
    """
    if modis0 is True and len(bstr_msg) % length != 0:
        # in this case it is not desired to have a remainder of bytes
        raise ParamClashError
    if len(bstr_msg) < length:
        raise ParamClashError
    if length < 0:
        raise ParamValueError
    restmsg = bstr_msg
    while restmsg:
        state = restmsg[:length]
        restmsg = restmsg[length:]
        yield state


def makeNDArrayFrom(bstr, a, b):
    """
    takes a byte string and returns it as a numpy ndarray, a as rows, b as columns. 4x4 for the moment
    TODO: make length variable
    """
    array = np.frombuffer(bstr, dtype=np.uint8)
    array.flags.writeable = True
    return array.reshape(a, b)


def andBytestrings(bstr1, bstr2):
    if len(bstr1) != len(bstr2):
        print("xorBytestrings: strings not of equal len")
        exit(1)
    return bytes([a & b for (a, b) in zip(bstr1, bstr2)])


def xorBytestrings(bstr1: bytes, bstr2: bytes, allow_diff_len: bool = False) -> object:
    if allow_diff_len == True:
        return bytes([a ^ b for (a, b) in zip(bstr1, bstr2)])
    if len(bstr1) != len(bstr2):
        print("xorBytestrings: strings not of equal len")
        exit(1)
    return bytes([a ^ b for (a, b) in zip(bstr1, bstr2)])


def xorStr1Str2AtPos(bstr1, bstr2, pos):
    # discovered slice function :)
    slice_bstr2 = slice(pos, pos + len(bstr1))
    if not bstr2[slice_bstr2]:
        return None
    return xorBytestrings(bstr1, bstr2[slice_bstr2], allow_diff_len=True)


def xorStr1AlongStr2(bstr1, bstr2):
    """
    Take a shorter byte string X and a longer one Y and xor X with
    the slices as long as X from every position in Y.
    X with len(X) bytes from pos. 0 in Y, from pos. 1 and so on.
    
    Return dict of indexes and corresponding xor result
    """
    len_str1 = len(bstr1)
    # + 0.4 gives math.ceil
    times_to_xor = round((len(bstr2) / len_str1) + 0.4)
    dict_pos_xor = dict()
    for i in range(len(bstr2)):
        xor = xorStr1Str2AtPos(bstr1, bstr2, i)
        dict_pos_xor[i] = xor
    return dict_pos_xor
