#!/usr/bin/env python3
import sys
import hashlib
import binascii
from Crypto.Cipher import DES

DES_CONSTANT=b'KGS!@#$%'

def des_lm_key(h):
    if len(h) != 7:
        raise ValueError('Key half must be exactly 7 characters')
    key = bytearray(8)
    key[0] = h[0] & 0xfe
    key[1] = ((h[0] << 7) & 0xff) | ((h[1] & 0xfc) >> 1)
    key[2] = ((h[1] << 6) & 0xff) | ((h[2] & 0xf8) >> 2)
    key[3] = ((h[2] << 5) & 0xff) | ((h[3] & 0xf0) >> 3)
    key[4] = ((h[3] << 4) & 0xff) | ((h[4] & 0xe0) >> 4)
    key[5] = ((h[4] << 3) & 0xff) | ((h[5] & 0xc0) >> 5)
    key[6] = ((h[5] << 2) & 0xff) | ((h[6] & 0x80) >> 6)
    key[7] = ((h[6] << 1) & 0xff)
    return bytes(key)
        
def des_lm_encrypt(k):
    des = DES.new(k, DES.MODE_ECB)
    return des.encrypt(DES_CONSTANT)

def ntlm_hash(pw):
    return hashlib.new('md4', pw.encode('utf-16-le')).hexdigest()

def lm_hash(pw):
    lm = (pw.upper() + '\x00' * 14)[:14]
    k0, k1 = des_lm_key(lm[:7].encode()), des_lm_key(lm[7:14].encode())
    return binascii.hexlify(des_lm_encrypt(k0) + des_lm_encrypt(k1)).decode()

pw = sys.argv[1]
print('  LM', lm_hash(pw))
print('NTLM', ntlm_hash(pw))
