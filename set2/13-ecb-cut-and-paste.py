#!/usr/bin/python3

import json
import urllib.parse
from crypto_algos import aes
from crypto_algos import misc
import os


def profileFor(mail_address):
    """
    takes a mail address and generate a json object for a user profile with that address
    """
    email = mail_address
    uid = 10
    role = 'user'

    profile = {'email': email, 'uid': uid, 'role': role}
    profile_json = json.dumps(profile)
    return profile_json


def _profEncode(json_profile):
    profile = json.loads(json_profile)
    return urllib.parse.urlencode(profile)


def _profDecode(urlenc_profile):
    prof_parsed = urllib.parse.parse_qsl(urlenc_profile)
    prof_str = json.dumps(dict(prof_parsed))
    return json.loads(prof_str)


def _encryptProfile(urlenc_profile, bstr_key):
	bstr_urlenc_profile = urlenc_profile
	return aes.aesEncrypt(bstr_urlenc_profile, bstr_key, 128, mode='ecb')


def _decryptProfile(encrypted_profile, bstr_key):
	return aes.aesDecrypt(encrypted_profile, bstr_key, 128, mode='ecb')


def decryptParse(encrypted_profile):
	bstr_key = b'1234567812345678'
	urlenc_prof = _decryptProfile(encrypted_profile, bstr_key).decode('ascii')
	urlenc_prof = misc.unpadPKCS7(urlenc_prof.encode('ascii'), 16)
	return _profDecode(urlenc_prof.decode('ascii'))

json_prof = profileFor('7890123456adminb@la.de')
#json_prof = profileFor('7@90.23456admin12345678123admin')
print(json_prof)
prof_encoded = _profEncode(json_prof)
print(prof_encoded)
print(_profDecode(prof_encoded))

bstr_key = b'1234567812345678'
prof_encoded = misc.padPKCS7(bytes(prof_encoded, 'ascii'),16)
prof_encrypted = _encryptProfile(prof_encoded, bstr_key)
print(prof_encrypted)

#prof_encrypted = b'\xc0x\xc6\xd1)~\xf3J\xb2\xbb\xe5\xd8\x02#\xa6!\xc3\x07\xa3s\xd8\x16\x87C\xb1\xe6\xbb\xf3\xf7\x00\xab!\x93^\xec\x11T\x9c&\xa2\x01\xb8{\xf7^:\x0e\x97'
prof_encrypted = b'\xbdC\x10\x15\xb8\xdd\xfb\x17\xf0\xa0ki\xd8\xa4cd\xbdC\x10\x15\xb8\xdd\xfb\x17\xf0\xa0ki\xd8\xa4cd\x93^\xec\x11T\x9c&\xa2\x01\xb8{\xf7^:\x0e\x97\xd9j\xa4+Y\x15\x1a\x9e\x9bY%\xfc\x9d\x95\xad\xaf'
prof_decrypted = _decryptProfile(prof_encrypted, bstr_key)
prof_decrypted = misc.unpadPKCS7(prof_decrypted, 16)
print(prof_decrypted)

print(decryptParse(prof_encrypted))