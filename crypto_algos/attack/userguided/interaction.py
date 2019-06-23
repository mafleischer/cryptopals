from crypto_algos.helpers import xorStr1Str2AtPos

def selectCipherItem(bstr_cipher_list: bytes) -> None:
    """
    Very general function. Select a cipher string from a list
    to do something with
    :return: None
    """
    pass


def printCipherClear(cipher_to_clear_dict, space_repr='[ ]', none_repr='[x]'):
    """
    pretty print ciphers to corresponding clear text.
    space_repr and none_repr (byte that's not discovered) should
    be 3 characters long
    :param cipher_to_clear_dict:
    :return: None
    """
    for item in cipher_to_clear_dict.items():
        cipher = item[0]
        clear = item[1]
        print('|', end='', flush=True)
        for pos in range(len(cipher)):
            # if no char or space
            #if clear[bindex] == 0x00 or clear[bindex] == 0x20:
            print('  {}  |'.format(pos), end='', flush=True)
        print('|', end='', flush=True)
        print()
        for pos in range(len(cipher)):
            print(' {} '.format(hex(cipher[pos])), end='', flush=True)
        # same length of course
        for pos in range(len(clear)):
            if clear[pos] == 0x00:
                print(' {} '.format(none_repr), end='', flush=True)
                continue
            if clear[pos] == 0x20:
                print(' {} '.format(space_repr), end='', flush=True)
                continue
            print(' {} '.format(chr(clear[pos])), end='', flush=True)



def xorInputWithSlice(bstr_cipher: bytes):
    """

    :param bstr_cipher:
    :return:
    """