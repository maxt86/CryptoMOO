"""
Crypto Modes Of Operation
Author: Max Tuchin (@maxt86)
"""


import enum
import math
import secrets

# You can use whatever cipher implementation you like.
# For this, change the 'ecb' field in the 'set_key method' below.
# Note that the 'encrypt' and 'decrypt' methods must be present in the ECB implementation.
from Crypto.Cipher import AES


__all__ = [
    'CryptoMOO',
    'Mode',
]


_BSIZE = 16
_CSIZE = 4


class Mode(enum.IntEnum):
    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4


class CryptoMOO:
    
    """ Crypto Modes Of Operation """
    
    def __init__(self, bsize=_BSIZE):
        if bsize < _BSIZE:
            self.bsize = _BSIZE
        else:
            self.bsize = bsize
        
        self.csize = _CSIZE
        
        self.key   = None
        self.ecb   = None
        self.mode  = None
        self.var   = None
    
    def get_key(self) -> bytes:
        return secrets.token_bytes(self.bsize)
    
    def set_key(self, key: bytes) -> None:
        if len(key) != self.bsize:
            return
        
        self.key = key
        
        # You can change the following as long as the implementation defines 'encrypt' and 'decrypt'.
        self.ecb = AES.new(key, AES.MODE_ECB)
    
    def get_iv(self) -> bytes:
        return secrets.token_bytes(self.bsize)
    
    def get_ctr(self) -> bytes:
        return (secrets.token_bytes(self.bsize - self.csize) + bytes([0])*4)
    
    def inc_ctr(self, ctr: bytes) -> bytes:
        ctr_int = int.from_bytes(ctr[-self.csize:], 'big')
        ctr_int += 1
        
        return (ctr[:-self.csize] + ctr_int.to_bytes(self.csize, 'big'))
    
    def set_mode(self, mode: Mode) -> None:
        self.mode = mode
    
    def block_cipher_encrypt(self, data: bytes) -> bytes:
        return self.ecb.encrypt(data)
    
    def block_cipher_decrypt(self, data: bytes) -> bytes:
        return self.ecb.decrypt(data)
    
    def pad(self, data: bytes, pkcs7: bool) -> bytes:
        npad = self.bsize - len(data)
        
        return (
            data + bytes([int(pkcs7) * npad]*npad)
            if npad >= 0
            else data
        )
    
    def unpad(self, data: bytes, pkcs7: bool) -> bytes:
        if not len(data):
            return data
        
        if not pkcs7:
            pos = len(data) - 1
            
            try:
                while not data[pos]:
                    pos -= 1
            except:
                return bytes()
            
            return data[:pos+1]
        
        num = data[-1]
        
        if not num or num > len(data):
            return data
        
        while num:
            num -= 1
            
            if data[len(data)-num-1] != data[-1]:
                return data
        
        return data[:len(data)-data[-1]]
    
    def process_block_encrypt(self, data: bytes, is_final_block: bool, padding: str) -> bytes:
        """ process_block_encrypt is responsible for the main logic, mode branching happens here. """
        
        if is_final_block:
            data = self.pad(data, padding == 'PKCS7')
        
        if self.mode == Mode.ECB:
            return self.block_cipher_encrypt(data)
        
        if self.mode == Mode.CBC:
            text = bytes([
                data[i] ^ self.var[i]
                for i in range(self.bsize)
            ])
            
            ctext = self.block_cipher_encrypt(text)
            
            self.var = ctext
            
            return ctext
        
        if self.mode == Mode.CFB:
            ctext = self.block_cipher_encrypt(self.var)
            
            ctext = bytes([
                ctext[i] ^ data[i]
                for i in range(self.bsize)
            ])
            
            self.var = ctext
            
            return ctext
        
        if self.mode == Mode.OFB:
            ctext = self.block_cipher_encrypt(self.var)
            
            self.var = ctext
            
            ctext = bytes([
                ctext[i] ^ data[i]
                for i in range(self.bsize)
            ])
            
            return ctext
        
        if self.mode == Mode.CTR:
            ctext = self.block_cipher_encrypt(self.var)
            
            self.var = self.inc_ctr(self.var)
            
            ctext = bytes([
                ctext[i] ^ data[i]
                for i in range(self.bsize)
            ])
            
            return ctext
    
    def process_block_decrypt(self, data: bytes, is_final_block: bool, padding: str) -> bytes:
        if self.mode == Mode.ECB:
            text = self.block_cipher_decrypt(data)
            
            if is_final_block:
                text = self.unpad(text, padding == 'PKCS7')
            
            return text
        
        if self.mode == Mode.CBC:
            text = self.block_cipher_decrypt(data)
            
            text = bytes([
                text[i] ^ self.var[i]
                for i in range(self.bsize)
            ])
            
            self.var = data
            
            if is_final_block:
                text = self.unpad(text, padding == 'PKCS7')
            
            return text
        
        if self.mode == Mode.CFB:
            text = self.block_cipher_encrypt(self.var)
            
            text = bytes([
                text[i] ^ data[i]
                for i in range(self.bsize)
            ])
            
            self.var = data
            
            if is_final_block:
                text = self.unpad(text, padding == 'PKCS7')
            
            return text
        
        if self.mode == Mode.OFB:
            text = self.block_cipher_encrypt(self.var)
            
            self.var = text
            
            text = bytes([
                text[i] ^ data[i]
                for i in range(self.bsize)
            ])
            
            if is_final_block:
                text = self.unpad(text, padding == 'PKCS7')
            
            return text
        
        if self.mode == Mode.CTR:
            text = self.block_cipher_encrypt(self.var)
            
            self.var = self.inc_ctr(self.var)
            
            text = bytes([
                text[i] ^ data[i]
                for i in range(self.bsize)
            ])
            
            if is_final_block:
                text = self.unpad(text, padding == 'PKCS7')
            
            return text
    
    def encrypt(self, data: bytes, iv: bytes = None) -> bytes:
        if iv is None:
            iv = (
                self.get_ctr()
                if self.mode == Mode.CTR
                else self.get_iv()
            )
        
        self.var = iv
        
        dsize = len(data)
        q = dsize // 16
        nb = dsize//self.bsize + int(bool(dsize % self.bsize)) + int(dsize/16 == q)
        
        enc = bytes()
        
        for i in range(nb):
            bs = self.bsize*i
            
            enc += self.process_block_encrypt(
                data[bs:bs+self.bsize], 
                i == nb-1,
                (
                    'PKCS7'
                    if (
                        self.mode == Mode.ECB or
                        self.mode == Mode.CBC
                    )
                    else 'NON'
                ),
            )
        
        return (iv + enc)
    
    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        self.var = iv
        
        dsize = len(data)
        nb = dsize // self.bsize
        
        diff = 0
        
        if dsize % self.bsize:
            near_bs = self.bsize * math.ceil(dsize / self.bsize)
            diff = near_bs - dsize
            
            data += bytes([0])*diff
            
            nb += 1

        dec = bytes()

        for i in range(nb):
            bs = self.bsize*i
            
            dec += self.process_block_decrypt(
                data[bs:bs+self.bsize], 
                i == nb-1,
                (
                    'PKCS7'
                    if self.mode in (
                        Mode.ECB,
                        Mode.CBC,
                    )
                    else 'NON'
                ),
            )
        
        if diff:
            return dec[:-diff]
        
        return dec
