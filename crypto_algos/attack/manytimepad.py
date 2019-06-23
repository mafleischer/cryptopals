#!/usr/bin/python3

from crypto_algos.helpers import xorBytestrings, xorStr1Str2AtPos, xorStr1AlongStr2

language_fragments = [b' the ', b'The ']  # , b'There ', b' there ', b' of ',
# b' my ', b'My ', b' do ']  # , b' that ', b'That ', b' that\'s ',
# b'That\'s ']


def _allCharsAllowed(bstr, bstr_include_chars):
    for b in bstr:
        if b not in bstr_include_chars:
            return False
    return True


def _buildKeyFromDict(dict_pos_keybytes):
    """
    build the key byte string from a dictionary holding
    position to bytes mappings
    """
    # determine key length
    sorted_dict_items = sorted(dict_pos_keybytes.items())
    rightmost_keybytes_item = sorted_dict_items[-1]
    keylen = rightmost_keybytes_item[0] + len(rightmost_keybytes_item[1])
    key = bytearray(keylen)
    for item in sorted_dict_items:
        pos = item[0]
        key_bytes = item[1]
        to = pos + len(key_bytes)
        key[pos:to] = key_bytes

    return bytes(key)


def _buildCipherClearDict(cipher_list):
    """
    build a dicitionary of ciphers to corresponding clear texts from
    a list holding the cipher byte strings.
    Used for pretty printing
    """
    cipher_to_clear = dict()
    for cipher in cipher_list:
        len_cipher = len(cipher)
        cipher_to_clear[cipher] = b'\x00' * len_cipher
    return cipher_to_clear


def manyTimePadAttackGuessWords(manytimes_bstr_list, language_fragments, include_chars=[]):
    """
    half automated, interactive
    """
    # shallow copy of list, equiv. of [:]
    crypted_lines = list(manytimes_bstr_list)
    lines_checked = []
    dict_pos_keybytes = dict()
    key = b''
    for crypted_line_1 in crypted_lines:
        lines_checked.append(crypted_line_1)
        crypted_lines.remove(crypted_line_1)

        for crypted_line_2 in crypted_lines:
            # this removes the many time pad which gives the xor'ed clear
            # messages
            xor_of_msgs = xorBytestrings(
                crypted_line_1, crypted_line_2, allow_diff_len=True)
            for fragment in language_fragments:
                print('Xor {0} along {1}'.format(fragment, xor_of_msgs))
                print('#' * 20)
                dict_pos_xor = xorStr1AlongStr2(fragment, xor_of_msgs)
                for item in sorted(dict_pos_xor.items()):
                    if not include_chars:
                        print('Pos. {0}: {1}'.format(item[0], item[1]))
                        continue
                    if _allCharsAllowed(item[1], include_chars):
                        print('Pos. {0}: {1}'.format(item[0], item[1]))
                answer_pos = input(
                    'Which one looks good? Enter position (enter for none, \'x\' for quit):')
                if answer_pos == 'x':
                    return _buildKeyFromDict(dict_pos_keybytes)
                if answer_pos == '':
                    continue
                answer_pos = int(answer_pos)

                # now check if the choice gives us actual key stream bytes
                result_clear = dict_pos_xor[answer_pos]

                hopefully_keybytes = xorStr1Str2AtPos(
                    result_clear, crypted_line_1, answer_pos)
                if hopefully_keybytes == xorStr1Str2AtPos(fragment, crypted_line_2, answer_pos):
                    dict_pos_keybytes[answer_pos] = hopefully_keybytes
                    continue

                hopefully_keybytes = xorStr1Str2AtPos(
                    result_clear, crypted_line_2, answer_pos)
                if hopefully_keybytes == xorStr1Str2AtPos(fragment, crypted_line_1, answer_pos):
                    dict_pos_keybytes[answer_pos] = hopefully_keybytes
                else:
                    print('Oops, doesn\'t look like key bytes!')

    return _buildKeyFromDict(dict_pos_keybytes)
