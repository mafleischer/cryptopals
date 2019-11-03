#!/usr/bin/python3

import types, re
from crypto_algos.challenge_specific import InvalidPKCS7Error
from crypto_algos.helpers import stateGenerator
from crypto_algos import aes


def cipherWFlippedBytesGenerator(bstr_cipher, *indexes):
    """ used for breaking cbc; flip the bytes in the positions given in indexes list;
    intended but not used so far
    """
    index_to_bytes = tuple(((i, bstr_cipher[i]) for i in indexes))
    for tup in index_to_bytes:
        new_cipher = bstr_cipher
        yield new_cipher


def _askOracle(bstr_cipher, fn_oracle):
    try:
        fn_oracle(bstr_cipher)
    except InvalidPKCS7Error:
        return False
    return True


def _modifyForPadding(barray_crafted, secret_state_b4_xor, next_padding):
    new_block = barray_crafted
    # not range + 1!
    for i in reversed(range(1, next_padding)):
    	new_block[-i] = secret_state_b4_xor[-i] ^ next_padding
    return new_block


def paddingOracleAttack(bstr_cipher, blocksize, fn_oracle, IV=None):
    """ Launch oracle attack on fn_oracle"""
    crafted_block = bytearray(blocksize * b'x')
    len_cipher = len(bstr_cipher)
    state_iter = stateGenerator(bstr_cipher, 16)
    state_list = [state for state in state_iter]
    num_states = len(state_list)

    if IV:
        first_block = IV
        states_to_decrypt = num_states
    else:
        first_block = state_list[0]
        state_list = state_list[1:]
        states_to_decrypt = num_states - 1

    clear = b''
    for i in range(states_to_decrypt):
        second_block = state_list[0]
        state_list = state_list[1:]
        print('First block: {0}'.format(first_block))
        print('Second block: {0}'.format(second_block))
        # b4 xor means: the stage in cbc where block is crypted but before xor'ed with
        # preceding cupher block
        secret_state_b4_xor = b''
        clear_block = b''
        
        for byte_index in reversed(range(blocksize)):
            padding_to_provoke = blocksize - byte_index
            
            for b in range(256):
                crafted_block[byte_index] = b
                #print(crafted_block)
                #print(bytes(crafted_block + second_block))
                #print('State {0}, index {1}, bf byte {2}'.format(i, byte_index, chr(b)))
                if _askOracle(bytes(crafted_block + second_block), fn_oracle):
                    secret_byte_b4_xor = crafted_block[byte_index]
                    secret_byte_b4_xor ^= padding_to_provoke
                    secret_state_b4_xor = bytes([secret_byte_b4_xor]) + secret_state_b4_xor
                    plain_byte = first_block[byte_index] ^ secret_byte_b4_xor
                    print('Discovered byte: {0}'.format(chr(plain_byte)))
                    #print('index {0}, bf byte {1}, cr. bl. byte: {2}, sec. b4 xor: {3}, 1st bl.: {4}'.format(byte_index, 
                    #    chr(b), crafted_block[byte_index], hex(secret_byte_b4_xor), hex(first_block[byte_index])))
                    clear_block = bytes([plain_byte]) + clear_block
                    # modify block for next padding
                    next_padding = padding_to_provoke + 1
                    crafted_block = _modifyForPadding(
                        crafted_block, secret_state_b4_xor, next_padding)
                    break
        clear += clear_block
        first_block = second_block

    return clear


def recoverIV(bstr_cipher: bytes, decryption_fn: types.FunctionType, num_bytes: int) -> bytes:
    """
    set 4 / challenge 27

    :param bstr_cipher:
    :param decryption_fn:
    :param num_bytes:
    :return:
    """
    first_block = bstr_cipher[:num_bytes]
    null_block = b'\x00' * num_bytes
    crafted_cipher = first_block
    msg = decryption_fn(bstr_cipher)