# CryptoMOO

CryptoMOO is a simple Python library which implements cryptographic modes of operation.

## API

The API is very simple and contains all the methods needed as follows:

  - ```get_key() -> bytes``` - get a key in a safe manner
  - ```set_key(key: bytes) -> None``` - set a key for encryption/decryption
  - ```get_iv() -> bytes``` - get an IV in a safe manner
  - ```get_ctr() -> bytes``` - get a counter in a safe manner
  - ```inc_ctr(ctr: bytes) -> bytes``` - returns the given counter incremented
  - ```set_mode(mode: Mode) -> None``` - mode of operation setup
  - ```block_cipher_encrypt(data: bytes) -> bytes``` - encrypt a block
  - ```block_cipher_decrypt(data: bytes) -> bytes``` - decrypt a block
  - ```pad(data: bytes, pkcs7: bool) -> bytes``` - pad a block (including an empty block)
  - ```unpad(data: bytes, pkcs7: bool) -> bytes``` - unpad a block (including an empty block)
  - ```proccess_block_encrypt(data: bytes, is_final_block: bool, padding: str) -> bytes``` - add one block for encryption
    - This method is responsible for the main logic, mode branching happens here.
  - ```process_block_decrypt(data: bytes, is_final_block: bool, padding: str) -> bytes``` - the same method, but for decryption
  - ```encrypt(data: bytes, iv: bytes = None) -> bytes``` - encrypt data of arbitrary length
  - ```decrypt(data: bytes, iv: bytes) -> bytes``` - decrypt data of arbitrary length

The methods that are most likely to be looked for in the first place are ```set_mode```, ```set_key```, ```encrypt``` and ```decrypt```.

## Sample decryption

The tests prove correctness of the primitives from the theoretical point of view.

To demonstrate how things work from the practical perspective, however, there is a separate program which decrypts the sample strings using the modes and the keys, all given in ```samples.txt```

You can see the decrypted strings by running ```sample_dec.py``` or by looking directly at the results in ```samples_dec.txt```
