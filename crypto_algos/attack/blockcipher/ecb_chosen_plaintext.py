from crypto_algos.attack.blockcipher import ecbmisc
import os


def createPlainBlocks():
    """
    NOT USED! But keep it, maybe in use in the future
    make blocks in printable char range
    """

    # for entire printable range
    #char_codes = [code for code in range(32, 127)]

    # this list must be in ascii order!
    char_list = ' !,-.?0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    char_codes = []
    for c in char_list:
        char_codes.append(ord(c))
    len_char_codes = len(char_codes)

    def carry(barray, bindex):
        """
        when least significant digit/char has flipped do the carry stuff

        bindex is the currently most significant used digit/char, i.e. greater than 32
        """

        # 15; last has been flipped already
        for b in reversed(range(bindex, 15)):
            if barray[b] == char_codes[len_char_codes - 1]:
                barray[b] = 32
            else:
                index = char_codes.index(barray[b])
                barray[b] = char_codes[index + 1]
                break

    # initial block
    block = bytearray(b'\x20' * 16)
    yield bytes(block)
    # start "counting" up for new blocks
    byte_index = 15
    while byte_index != -1:
        for char in range(33, 127):
            if block[15] == char_codes[len_char_codes - 1]:
                block[15] = 0x20
                carry(block, byte_index)
                # if most significant byte flipped go up and count that
                # byte one up
                if block[byte_index] == 32:
                    byte_index -= 1
                    block[byte_index] = char_codes[1]
                yield bytes(block)
            else:
                index = char_codes.index(block[15])
                block[15] = char_codes[index + 1]
                yield bytes(block)


def _findECBCipherBlockJumpLen(secret_fn):
    """
    find the length len of the chosen plaintext string that causes the cipher length in blocks to be increased by one.
    return len - 1: that is the length of the cipher where no padding was applied
    """
    cipher = secret_fn(b'')
    len_cipher = len(cipher)
    add = b'x'
    len_added = len(add)
    for i in range(15):
        len_with_added = len(secret_fn(add))
        if len_cipher < len_with_added:
            return len_added - 1
        else:
            len_added += 1
            add += b'x'


def _ecbByteOracle(bstr_chosen, secret_fn, byte_offset):
    """
    check if the chosen plain text portion prepended to bstr_append encrypted is the same as byte_offset bytes cut off at
    the end of the chosen plain text encrypted (that means num bytes shifted into the chosen plain text area)
    """
    cipher_nocut = secret_fn(bstr_chosen)
    cipher_cut = secret_fn(bstr_chosen[:-byte_offset])
    # print(bstr_chosen[:-1])
    # print(cipher_nocut)
    # print(cipher_cut)
    len_chosen = len(bstr_chosen)
    # if cipher_nocut[len_chosen - 1] == cipher_cut[len_chosen - 1]:
    block_start = len_chosen - 1 - 15
    block_end = len_chosen - 1
    # if cipher_nocut[len_chosen - 1] == cipher_cut[len_chosen - 1]:
    if cipher_nocut[block_start:block_end + 1] == cipher_cut[block_start:block_end + 1]:
        #    print(chr(cipher_nocut[len_chosen - 1]))
        #    print(chr(cipher_cut[len_chosen - 1]))
        return True
    else:
        return False


def makeBlockDict(bstr_block_short):
    """
    make a dicitionary mapping cipher blocks to byte last position;
    apparently more than one byte in last position
    can result in the same cipher byte in the cipher block!
    """
    pass


def ecbChosenPlaintext(secret_fn):
    if not ecbmisc.isECB(secret_fn(b'A' * 16 * 100)):
        print("Cipher is not ECB!")
        exit(1)
    # for entire printable range:
    # chars_to_test = bytes(code for code in range(32, 127))
    chars_to_test = b' \',-.?05abcdeghijlmnoprstuvwyDINRTW\n'
    blocksize = ecbmisc.discoverBlocksize(secret_fn(b''))
    len_cipher_no_chosen = len(secret_fn(b''))
    # length of chosen plain % [blocksize] with which no padding is applied = length of
    # the padding with no chosen plain
    len_padding = _findECBCipherBlockJumpLen(secret_fn)
    len_cipher_wo_padding = len_cipher_no_chosen - len_padding
    # this is one byte short. The test byte will be appended in the loop
    # below
    #bstr_chosen_plain = bytearray(os.urandom(len_cipher_no_chosen))
    #del bstr_chosen_plain[-1]
    bstr_chosen_plain = bytearray(b'x') * (len_cipher_no_chosen - 1)
    # length of chosen that has length of the secret portion + secret
    # portion; w/o padding
    len_chosen = len_cipher_no_chosen

    clear = b''
    num_discovered_bytes = 0
    while num_discovered_bytes != len_cipher_wo_padding:
        for char in chars_to_test:
            #print("Testing byte {0}".format(chr(char)))
            bstr_chosen_plain += bytes([char])

            #if _ecbByteOracle(b'xxxxxxRollin\' ic', secret_fn, 10):
                # if _ecbByteOracle(bstr_chosen_plain, secret_fn, 10):
                #print("Test true")
            #else:
                #print("Test false")
            #print(bstr_chosen_plain)

            if _ecbByteOracle(bstr_chosen_plain, secret_fn, num_discovered_bytes + 1):
                print("Discovered byte {0}".format(chr(char)))
                clear += bytes([char])
                num_discovered_bytes += 1
                del bstr_chosen_plain[0]
                break
            else:
                del bstr_chosen_plain[-1]

    return clear


def ecbChosenPlaintextPrepend(secret_fn):
    if not ecbmisc.isECB(secret_fn(b'A' * 16 * 100)):
        print("Cipher is not ECB!")
        exit(1)
    # for entire printable range:
    # chars_to_test = bytes(code for code in range(32, 127))
    chars_to_test = b' \',-.?05abcdeghijlmnoprstuvwyDINRTW\n'
    blocksize = ecbmisc.discoverBlocksize(secret_fn(b''))
    len_cipher_no_chosen = len(secret_fn(b''))
    # length of chosen plain % [blocksize] with which no padding is applied = length of
    # the padding with no chosen plain
    len_padding = _findECBCipherBlockJumpLen(secret_fn)
    len_cipher_wo_padding = len_cipher_no_chosen - len_padding
    # this is one byte short. The test byte will be appended in the loop
    # below
    #bstr_chosen_plain = bytearray(os.urandom(len_cipher_no_chosen))
    #del bstr_chosen_plain[-1]
    bstr_chosen_plain = bytearray(b'x') * (len_cipher_no_chosen - 1)
    # length of chosen that has length of the secret portion + secret
    # portion; w/o padding
    len_chosen = len_cipher_no_chosen

    clear = b''
    num_discovered_bytes = 0
    while num_discovered_bytes != len_cipher_wo_padding:
        for char in chars_to_test:
            #print("Testing byte {0}".format(chr(char)))
            bstr_chosen_plain += bytes([char])

            #if _ecbByteOracle(b'xxxxxxRollin\' ic', secret_fn, 10):
                # if _ecbByteOracle(bstr_chosen_plain, secret_fn, 10):
                #print("Test true")
            #else:
                #print("Test false")
            #print(bstr_chosen_plain)

            if _ecbByteOracle(bstr_chosen_plain, secret_fn, num_discovered_bytes + 1):
                print("Discovered byte {0}".format(chr(char)))
                clear += bytes([char])
                num_discovered_bytes += 1
                del bstr_chosen_plain[0]
                break
            else:
                del bstr_chosen_plain[-1]

    return clear