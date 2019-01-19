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
    if cipher_nocut[len_chosen - 1] == cipher_cut[len_chosen - 1]:
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
    # for entire printable range
    # chars_to_test = bytes(code for code in range(32, 127))
    chars_to_test = b' \',-.?05abcdeghijlmnoprstuvwyDNRTW\n'
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

    # a map of {< int, is byte offset in secret portion> : <integer list here, byte values that fit for offset>}
    dict_pos_candidates = dict()
    clear = bytearray()
    num_discovered_bytes = 0
    while num_discovered_bytes != len_cipher_wo_padding:
        # position of byte we want to discover in the secret cipher portion
        byte_offset = len(clear) + 1
        # just for having a cipher with entire chosen plain to lookup the
        # byte in the secret portion
        cipher = secret_fn(bstr_chosen_plain + b'x')
        byte_candidates = []
        found = 0
        while found == 0:
            next_clear = b''
            for byte_to_test_for in chars_to_test:

                #if byte_offset == 10 and chr(byte_to_test_for) == 'c':
                #    byte_to_test_for = ord('n')
                print("Offset {0} and byte {1}".format(byte_offset, chr(byte_to_test_for)))

                if _ecbByteOracle(bstr_chosen_plain + (b'%c' % byte_to_test_for), secret_fn, byte_offset):
                    found = 1
                    print("Discovered byte {0} for byte offset {1}".format(
                        chr(byte_to_test_for), byte_offset))
                    # append the first byte for that offset to clear text
                    if not byte_candidates:
                        next_in_clear = byte_to_test_for
                    # append all other bytes for that offset to candidate list
                    else:
                        byte_candidates.append(bytes([byte_to_test_for]))
                    # break
            clear += b'%c' % next_in_clear
            bstr_chosen_plain += b'%c' % next_in_clear
            del bstr_chosen_plain[0]
            print(clear)
            print(byte_candidates)



            if found == 0:
                
                print(dict_pos_candidates)
                print(byte_offset)

                print("Byte not found. This is the clear text so far:\n {0}".format(clear))
                backsteps = int(input("Go back how many bytes?: "))
                for pos in range(byte_offset - backsteps + 1, byte_offset + 1):
                    if pos in dict_pos_candidates:
                        del dict_pos_candidates[pos]

                byte_offset -= backsteps
                num_discovered_bytes -= backsteps

                if not dict_pos_candidates[byte_offset]:
                    print("No more byte candidates! Exiting.")
                    exit(1)
                next_byte = dict_pos_candidates[byte_offset][0]
                del clear[-backsteps:]
                clear[-1] = b'%c' % next_byte
                del bstr_chosen_plain[-backsteps:]
                bstr_chosen_plain[-1] = b'%c' % next_byte
                bstr_chosen_plain = (b'x' * backsteps) + bstr_chosen_plain
                del dict_pos_candidates[byte_offset][0]
                found = 1
            else:
                dict_pos_candidates[byte_offset] = byte_candidates
                byte_candidates = []
                num_discovered_bytes += 1

    return clear
