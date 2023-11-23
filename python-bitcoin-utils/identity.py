from bitcoinutils.keys import P2pkhAddress, PrivateKey, PublicKey
import init
#import consts
import binascii
from helper import decompress_pubkey

init.init_network()

class Id:
    """
    Helper class for handling identity related keys and addresses easily
    """
    def __init__(self, sk: str):
        self.sk = PrivateKey(secret_exponent=int(sk,16))
        #print("Private Key: ", binascii.hexlify(PublicKey.to_bytes(self.sk)))
        self.pk = self.sk.get_public_key()
        #print("Compressed Public Key: ", self, "  ", self.sk.get_public_key().to_hex())
        #print(binascii.hexlify(decompress_pubkey(binascii.unhexlify('0229b3e0919adc41a316aad4f41444d9bf3a9b639550f2aa735676ffff25ba3898'))).decode())
        #print("Uncompressed Public Key: ", binascii.hexlify(decompress_pubkey(binascii.unhexlify(self.sk.get_public_key().to_hex()))).decode())
        self.addr = self.pk.get_address().to_string()
        #print("address: ", self.addr)
        self.p2pkh = P2pkhAddress(self.addr).to_script_pub_key()
        #print("p2pkh: ", self.p2pkh)