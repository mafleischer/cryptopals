#!/usr/bin/python3

from crypto_algos.helpers import xorBytestrings, xorStr1AlongStr2

language_fragments = [b' the ', b'The ']#, b'There ', b' there ', b' of ',
                      #b' my ', b'My ', b' do ']  # , b' that ', b'That ', b' that\'s ', b'That\'s ']


def _allCharsAllowed(bstr, bstr_include_chars):
    for b in bstr:
        if b not in bstr_include_chars:
            return False
    return True


def manyTimePadAttackGuessWords(manytimes_bstr_list, language_fragments, include_chars=[]):
    """
    half automated, interactive
    """
    crypted_lines = manytimes_bstr_list
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
                answer_pos = input('Which one looks good? Enter position (enter for none, \'x\' for quit):')
                if answer_pos == 'x':
                    return key
                if answer_pos == '':
                    continue

