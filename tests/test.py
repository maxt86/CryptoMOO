#!/usr/bin/env python3
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptomoo


def main(argv=()):
    print('test modes and padding\n\n')
    
    bs = 16
    
    cmoo = cryptomoo.CryptoMOO(bs)
    
    plain0 = b'0123456789abcdef'
    plain1 = b'........................................' # 2.5 blocks
    
    print(f'plain0: {plain0}')
    print(f'len: {len(plain0)}')
    print()
    
    print(f'plain1: {plain1}')
    print(f'len: {len(plain1)}')
    print()
    
    key = cmoo.get_key()
    
    cmoo.set_key(key)
    print(f'\nkey: {key.hex()}')
    print()
    
    #<ecb>
    cmoo.set_mode(cryptomoo.Mode.ECB)
    print(f'\nmode: ecb')
    print()
    
    iv0 = cmoo.get_iv()
    iv1 = cmoo.get_iv()
    
    enc0 = cmoo.encrypt(plain0, iv0)
    enc1 = cmoo.encrypt(plain1, iv1)
    
    print(f'enc0: {enc0.hex()}')
    print(f'len: {len(enc0)} bytes')
    print()
    
    print(f'enc1: {enc1.hex()}')
    print(f'len: {len(enc1)} bytes')
    print()
    
    dec0 = cmoo.decrypt(enc0[bs:], enc0[:bs])
    dec1 = cmoo.decrypt(enc1[bs:], enc1[:bs])
    
    print(f'dec0: {dec0}')
    print(f'dec1: {dec1}')
    print()
    print('success' if dec0 == plain0 and dec1 == plain1 else 'fail')
    print()
    #</ecb>
    
    #<cbc>
    cmoo.set_mode(cryptomoo.Mode.CBC)
    print(f'\nmode: cbc')
    print()
    
    iv0 = cmoo.get_iv()
    iv1 = cmoo.get_iv()
    
    enc0 = cmoo.encrypt(plain0, iv0)
    enc1 = cmoo.encrypt(plain1, iv1)
    
    print(f'enc0: {enc0.hex()}')
    print(f'len: {len(enc0)} bytes')
    print()
    
    print(f'enc1: {enc1.hex()}')
    print(f'len: {len(enc1)} bytes')
    print()
    
    dec0 = cmoo.decrypt(enc0[bs:], enc0[:bs])
    dec1 = cmoo.decrypt(enc1[bs:], enc1[:bs])
    
    print(f'dec0: {dec0}')
    print(f'dec1: {dec1}')
    print()
    print('success' if dec0 == plain0 and dec1 == plain1 else 'fail')
    print()
    #</cbc>
    
    #<cfb>
    cmoo.set_mode(cryptomoo.Mode.CFB)
    print(f'\nmode: cfb')
    print()
    
    iv0 = cmoo.get_iv()
    iv1 = cmoo.get_iv()
    
    enc0 = cmoo.encrypt(plain0, iv0)
    enc1 = cmoo.encrypt(plain1, iv1)
    
    print(f'enc0: {enc0.hex()}')
    print(f'len: {len(enc0)} bytes')
    print()
    
    print(f'enc1: {enc1.hex()}')
    print(f'len: {len(enc1)} bytes')
    print()
    
    dec0 = cmoo.decrypt(enc0[bs:], enc0[:bs])
    dec1 = cmoo.decrypt(enc1[bs:], enc1[:bs])
    
    print(f'dec0: {dec0}')
    print(f'dec1: {dec1}')
    print()
    print('success' if dec0 == plain0 and dec1 == plain1 else 'fail')
    print()
    #</cfb>
    
    #<ofb>
    cmoo.set_mode(cryptomoo.Mode.OFB)
    print(f'\nmode: ofb')
    print()
    
    iv0 = cmoo.get_iv()
    iv1 = cmoo.get_iv()
    
    enc0 = cmoo.encrypt(plain0, iv0)
    enc1 = cmoo.encrypt(plain1, iv1)
    
    print(f'enc0: {enc0.hex()}')
    print(f'len: {len(enc0)} bytes')
    print()
    
    print(f'enc1: {enc1.hex()}')
    print(f'len: {len(enc1)} bytes')
    print()
    
    dec0 = cmoo.decrypt(enc0[bs:], enc0[:bs])
    dec1 = cmoo.decrypt(enc1[bs:], enc1[:bs])
    
    print(f'dec0: {dec0}')
    print(f'dec1: {dec1}')
    print()
    print('success' if dec0 == plain0 and dec1 == plain1 else 'fail')
    print()
    #</ofb>
    
    #<ctr>
    cmoo.set_mode(cryptomoo.Mode.CTR)
    print(f'\nmode: ctr')
    print()
    
    ctr0 = cmoo.get_ctr()
    ctr1 = cmoo.get_ctr()
    
    enc0 = cmoo.encrypt(plain0, ctr0)
    enc1 = cmoo.encrypt(plain1, ctr1)
    
    print(f'enc0: {enc0.hex()}')
    print(f'len: {len(enc0)} bytes')
    print()
    
    print(f'enc1: {enc1.hex()}')
    print(f'len: {len(enc1)} bytes')
    print()
    
    dec0 = cmoo.decrypt(enc0[bs:], enc0[:bs])
    dec1 = cmoo.decrypt(enc1[bs:], enc1[:bs])
    
    print(f'dec0: {dec0}')
    print(f'dec1: {dec1}')
    print()
    print('success' if dec0 == plain0 and dec1 == plain1 else 'fail')
    #</ctr>
    
    input()
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
