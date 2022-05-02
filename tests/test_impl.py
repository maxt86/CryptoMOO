#!/usr/bin/env python3
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import cryptomoo


def main(argv=()):
    print('test implementation\n\n')
    
    bs = 16
    
    cmoo = cryptomoo.CryptoMOO(bs)
    
    plain0 = b'123456789abcdef'
    plain1 = b'0123456789abcdef'
    
    print(f'plain0: {plain0}')
    print(f'len: {len(plain0)}')
    print()
    
    print(f'plain1: {plain1}')
    print(f'len: {len(plain1)}')
    print()
    
    key = cmoo.get_key()
    cmoo.set_key(key)
    
    cmoo.set_mode(cryptomoo.Mode.CBC)
    
    iv0 = cmoo.get_iv()
    cbc0 = AES.new(key, AES.MODE_CBC, iv0)
    
    enc0 = cbc0.encrypt(pad(plain0, bs)).hex()
    enc0_cmoo = cmoo.encrypt(plain0, iv0).hex()[2*bs:] # 1 byte = 2 hex symbols
    print(f'enc0:      {enc0}')
    print(f'enc0_cmoo: {enc0_cmoo}')
    print('success' if enc0 == enc0_cmoo else 'fail')
    
    print()
    
    iv1 = cmoo.get_iv()
    cbc1 = AES.new(key, AES.MODE_CBC, iv1)
    
    enc1 = cbc1.encrypt(pad(plain1, bs)).hex()
    enc1_cmoo = cmoo.encrypt(plain1, iv1).hex()[2*bs:]
    print(f'enc1:      {enc1}')
    print(f'enc1_cmoo: {enc1_cmoo}')
    print('success' if enc1 == enc1_cmoo else 'fail')
    
    input()
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
