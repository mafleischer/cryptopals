from crypto_algos.attack.blockcipher import ecbmisc
from crypto_algos import logger
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
    return len - 1: that is the length of the chosen plain where no padding was applied
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


def _stripBytesUpToSecret(cipher, blocksize):
    pos = _findDuplicateBlockPairs(cipher, blocksize)
    if pos is not None:
        return cipher[pos:]
    else:
        return None


def _findECBCipherBlockJumpLenPrepend(secret_fn, blocksize):
    """
    find the length len of the chosen plaintext string that causes the cipher length in blocks to be increased by one.
    return len - 1: that is the length of the chosen plain where no padding was applied; for chal. 14
    """

    bstr_marking_blocks = b'XXXXXXXXXXXXXXXXXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    while True:
        cipher = secret_fn(bstr_marking_blocks)
        new_cipher = _stripBytesUpToSecret(cipher, blocksize)
        if new_cipher is not None:
            cipher = new_cipher
            break
    # w/o random bytes
    len_cipher = len(cipher)
    add = b'x'
    len_added = len(add)
    for i in range(15):
        while True:
            cipher = secret_fn(bstr_marking_blocks + add)
            new_cipher = _stripBytesUpToSecret(cipher, blocksize)
            if new_cipher is not None:
                cipher = new_cipher
                break

        len_with_added = len(cipher)
        if len_cipher < len_with_added:
            return len_added - 1
        else:
            len_added += 1
            add += b'x'


def _findDuplicateBlockPairs(bstr, blocksize):
    """ Find neighboring identical blocks and if found return
    the index right after them; Used in harder chosen plain text attack"""
    length = len(bstr)
    for i in range(0, length - (2 * blocksize), blocksize):
        state = bstr[i:i + blocksize]
        neighbor = bstr[i + blocksize: i + (2 * blocksize)]
        if state == neighbor:
            after_mark = i + (2 * blocksize)
            logger.debug(
                'Found duplicate block neighbors: {0}\nPosition after: {1}'.format(state, after_mark))
            return after_mark
    logger.warning('Found no duplicate blocks.')
    return None


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


def _ecbByteOraclePrepend(bstr_chosen, secret_fn, byte_offset):
    """
    check if the chosen plain text portion prepended to bstr_append encrypted is the same as byte_offset bytes cut off at
    the end of the chosen plain text encrypted (that means num bytes shifted into the chosen plain text area)
    """

    blocksize = 16
    while True:
        cipher_nocut = secret_fn(bstr_chosen)
        pos = _findDuplicateBlockPairs(cipher_nocut, blocksize)
        # if we are blockaligned, cut off radom bytes and the marking blocks
        if pos is not None:
            cipher_nocut = cipher_nocut[pos:]
            break

    while True:
        cipher_cut = secret_fn(bstr_chosen[:-byte_offset])
        pos = _findDuplicateBlockPairs(cipher_cut, blocksize)
        # if we are blockaligned, cut off radom bytes and the marking blocks
        if pos is not None:
            cipher_cut = cipher_cut[pos:]
            break
    # print(bstr_chosen[:-1])
    # print(cipher_nocut)
    # print(cipher_cut)

    # w/o marking
    len_chosen = len(bstr_chosen) - 48
    # if cipher_nocut[len_chosen - 1] == cipher_cut[len_chosen - 1]:
    block_start = len_chosen - 16
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

            # if _ecbByteOracle(b'xxxxxxRollin\' ic', secret_fn, 10):
            # if _ecbByteOracle(bstr_chosen_plain, secret_fn, 10):
            #print("Test true")
            # else:
            #print("Test false")
            # print(bstr_chosen_plain)

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
    """
    Since our secret is encrypted randomnum_of_randombytes + chosen_plain + secret_plain
    we have to find out the starting point of our chosen plain in the cipher text.
    Afterwards we are keeping track of the offset from block alignment by the means
    marking blocks, two (both the same) for each possible offset, all pairs next to
    each other at the beginning:

    [...random_bytes...] + [offset0_block][offset0_block][offset1_block][offset1_block]
    ....+[rest_chosen_plain][secret_plain]

    Offset 1 means one byte short to block alignment. So input blocks [XXXXXXXXXXXXXXXA][AAAAAAAAAAAAAAAA][AAAAAAAAAAAAAAAX]
    will be [RXXXXXXXXXXXXXXX][AAAAAAAAAAAAAAAA][AAAAAAAAAAAAAAAA] after the random bytes have been prepended.
    (R is one of the random bytes shifted in). We can tell that this means we have an offset of 1 after we got the
    secret portion length (we do this in the beginning simply by passing only two identical blocks. When we get two
    identical blocks in the cipher we count from there onward). We subtract that many bytes at the end and count the remaining
    blocks after the two identical ones.

    For exapmle when we have a number of random bytes that causes the text to be shifted by 15 off
    of block alignment (blocksize 16) we will have two identical blocks in the cipher of our chosen
    plain text, namely the offset15_blocks blocks. That
    So when we are probing for the first byte of the secret we check for the offset15 block in
    the cipher. The padded clear looks like this:
    [...random bytes...] + [gibberish, "invisible offset blocks"][offset15_block][offset15_block]+
    [more_chosen_plain][AAAAAAAAAAAAAAAb][rest_secret][X\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15\x15]
    """

    if not ecbmisc.isECB(secret_fn(b'A' * 16 * 100)):
        print("Cipher is not ECB!")
        exit(1)
    # for entire printable range:
    # chars_to_test = bytes(code for code in range(32, 127))
    chars_to_test = b' \',-.?05abcdeghijlmnoprstuvwyDINRTW\n'
    blocksize = ecbmisc.discoverBlocksize(secret_fn(b''))
    # length of chosen plain % [blocksize] with which no padding is applied = length of
    # the padding with no chosen plain
    logger.info('##### Creating marking blocks #####')
    # make marking blocks, starting with offset 0 blocks
    bstr_offset0_blocks = b'XXXXXXXXXXXXXXXXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    bstr_marking_blocks = bstr_offset0_blocks
    for offset in range(1, blocksize):
        bstr_prefix = b'x' * (blocksize - offset)
        bstr_offsetx_blocks = b'A' * 2 * blocksize
        bstr_suffix = b'x' * offset
        bstr_marking_blocks += bstr_prefix + bstr_offsetx_blocks + bstr_suffix
        logger.debug('Created marking block {0}'.format(
            bstr_prefix + bstr_offsetx_blocks + bstr_suffix))
    logger.debug('Finished marking blocks:\n{0}'.format(bstr_marking_blocks))

    jump_len = _findECBCipherBlockJumpLenPrepend(secret_fn, blocksize)

    logger.info('##### Find secret portion length #####')
    # find the secret portion length (includes padding)
    while True:
        cipher = secret_fn(bstr_offset0_blocks)
        pos = _findDuplicateBlockPairs(cipher, blocksize)
        if pos is not None:
            secret_length = len(cipher) - pos - blocksize
            break

    logger.info(
        'Secret portion length (includes padding): {0}'.format(secret_length))

    # this is one byte short. The test byte will be appended in the loop
    # below; minus two marking blocks minus 16 byte padding
    bstr_chosen_plain = bytearray(b'x') * (secret_length - 1)
    # length of chosen that has length of the secret portion + secret
    # portion;
    len_cipher_no_chosen = secret_length
    len_cipher_wo_padding = len_cipher_no_chosen

    secret_length -=  jump_len

    clear = b''
    # oracle cuts off num_discovered + 1
    num_discovered_bytes = 0
    while num_discovered_bytes != secret_length:
        for char in chars_to_test:
            # but offset blocks at the beginning
            # complementary: e.g. if the oracle cuts 15 bytes of a block we need
            # offset 1 block
            offsetblock_index_start = num_discovered_bytes % blocksize + 1
            offsetblock_index_start *= 3 * blocksize
            offsetblock_index_start *= -1
            offsetblock_index_end = offsetblock_index_start + 3 * blocksize
            if offsetblock_index_end == 0:
                offsetblock_index_end = None
            current_offset_blocks = bstr_marking_blocks[
                offsetblock_index_start: offsetblock_index_end]
            logger.debug('Choosing offset blocks for the chosen plain:\n{0}'.format(
                current_offset_blocks))
            # bstr_chosen_plain = bytearray(
            #    current_offset_blocks) + bstr_chosen_plain
            bstr_chosen_plain = bytearray(
                bstr_offset0_blocks) + bstr_chosen_plain
            bstr_chosen_plain += bytes([char])
            logger.debug('Chosen plain text:\n{0}'.format(bstr_chosen_plain))

            if _ecbByteOraclePrepend(bstr_chosen_plain, secret_fn, num_discovered_bytes + 1):
                print("Discovered byte {0}".format(chr(char)))
                clear += bytes([char])
                num_discovered_bytes += 1
                # remove marking blocks first
                del bstr_chosen_plain[0:48]
                # then one x byte
                del bstr_chosen_plain[0]
                break
            else:
                del bstr_chosen_plain[0:48]
                del bstr_chosen_plain[-1]

    return clear
