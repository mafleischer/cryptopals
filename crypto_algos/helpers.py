import numpy as np

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


def stateGenerator(bstr_msg):
    """
    takes the whole length of the message as a byte
    string and returns blocks of it as byte string
    TODO: make block length variable
    """
    if len(bstr_msg) % 16 != 0:
        print("stateGenerator: msg len % 16 != 0")
        exit(1)
    restmsg = bstr_msg
    while len(restmsg) > 0:
        state = restmsg[:16]
        restmsg = restmsg[16:]
        yield state


def makeNDArrayFrom(bstr, a, b):
    """
    takes a byte string and returns it as a numpy ndarray, a as rows, b as columns. 4x4 for the moment
    TODO: make length variable
    """
    array = np.frombuffer(bstr, dtype=np.uint8)
    array.flags.writeable = True
    return array.reshape(a, b)


def xorBytestrings(bstr1, bstr2):
    if len(bstr1) != len(bstr2):
        print("xorBytestrings: strings not of equal len")
        exit(1)
    return bytes([a ^ b for (a, b) in zip(bstr1, bstr2)])