import binascii
import hashlib
from bitcoinutils.transactions import Transaction
import random

random.seed(7) # fix seed for showcase purposes

def gen_secret() -> str:
    """
        Replace this method with a secure random generator for any real world application
    """
    r = random.randrange(0, 255) # INSECURE, just for demo
    r = hex(r)[2:]
    if len(r) == 1:
        text = "0".format(r)
        return text
    return r

def hash256(hexstring: str) -> str:
    data = binascii.unhexlify(hexstring)
    h1 = hashlib.sha256(data)
    h2 = hashlib.sha256(h1.digest())
    return h2.hexdigest()

def decompress_pubkey(pk):
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = int.from_bytes(pk[1:33], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != pk[0] % 2:
        y = p - y
    y = y.to_bytes(32, byteorder='big')
    return b'\x04' + pk[1:33] + y

#def print_tx(tx: Transaction, name: str) -> None:
#    print(f'{name}: {int(len(tx.serialize())/2)} Bytes')
#    print(tx.serialize())
#    print('----------------------------------')

