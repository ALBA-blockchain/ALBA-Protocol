from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.script import Script
from bitcoinutils.keys import P2pkhAddress, PrivateKey, PublicKey
from schnorr import schnorr_sign
from identity import Id
from helper import hash256, gen_secret
import init
import scripts
import txs
import hashlib
import struct
from binascii import unhexlify, hexlify
from bitcoinutils.constants import SIGHASH_ALL

init.init_network()

#ids chosen at random
id_P = Id('d44348ff037a7f65bcf9b7c86181828f5e05dbfe6cf2efe9af6362c8d53a00b0') #address is mhdTzofrDHXF18US18Y6ZfV5JhqCxa13yh
id_V = Id('b45349ff037a7f65bcf9b7c86181828f5e05dbfe6cf2efe9af6362c8d53a00b0') #address is my6e3Kf7vUEW9dvdhS9jrMHUjsL1k95csk 

# # # # # # # #
# Funding transaction
# # # # # # # #

#inputs
tx_in_P = TxInput('60ee896b9efc7553d868215cdb4c488827fb833739af75087dbe23536cc0b61c', 1) 
tx_in_V = TxInput('e618afd8ee491a005d665e1321334cc396eb4622af737e487134776f76a721d0', 1) 
#outputs
tx_out_multisig = TxOutput(9000, scripts.get_script_ft_output(id_P, id_V)) 
#tx_out_payback = TxOutput(9100, id_P.p2pkh)
#construct tx
tx = Transaction([tx_in_P, tx_in_V], [tx_out_multisig])
#compute signatures
sig_P = id_P.sk.sign_input(tx, 0 , id_P.p2pkh) 
sig_V = id_V.sk.sign_input(tx, 1 , id_V.p2pkh) 
# unlocking script for the input
tx_in_P.script_sig = Script([sig_P, id_P.pk.to_hex()])
tx_in_V.script_sig = Script([sig_V, id_V.pk.to_hex()]) 

# Schnorr attempt
""" txid_test = bytes.fromhex('88aafc3e9e44f482cec7e9fb6ca739564a39d420e9b0ed69dedcee61171891ad')
aux_rand = bytes.fromhex('d44348ff037a7f65bcf9b7c86181828f5e05dbfe6cf2efe9af6362c8d53a00b0')
seckey = bytes.fromhex('0eb7aa2f67ce6e265e571456fec8789d7ee6c7b341ff444f2846623f36ae083f')
sig_P = schnorr_sign(txid_test, seckey, aux_rand) 
#sig_V = schnorr_sign(txid_test, id_V.sk.to_bytes, aux_rand)
print("schnorr sig ")
print(sig_P.hex())
print(" ")
print(id_P.pk)  """

print("Funding transaction: ", tx.serialize()) 

"""
# # # # # # # #
# Spend funding tx!
# # # # # # # #
 
#inputs 
tx_in_forfees = TxInput('d7a751512420e267ad5abbfdca6c2f9133ab61e7952d728db868d3bc50d89110', 0)
tx_in_ft = TxInput('d7a751512420e267ad5abbfdca6c2f9133ab61e7952d728db868d3bc50d89110', 1) 
#outputs
tx_out = TxOutput(25880, scripts.get_script_ft_output(id_P, id_V))
# construct tx
tx = Transaction([tx_in_forfees, tx_in_ft], [tx_out])
scriptFToutput = scripts.get_script_ft_output(id_P, id_V)

print(tx.serialize())

#compute signatures
sig_P = id_P.sk.sign_input(tx, 1 , scriptFToutput) 
sig_V = id_V.sk.sign_input(tx, 1 , scriptFToutput) 
#print("SigV: ", sig_V)
sig_P_forfees = id_P.sk.sign_input(tx, 0 , id_P.p2pkh) 
# unlocking script for the input
tx_in_ft.script_sig = Script([sig_V, sig_P]) #note P and V are reversed!
tx_in_forfees.script_sig = Script([sig_P_forfees, id_P.pk.to_hex()])

print(tx.serialize())
"""


# # # # # # # #
# Create unlocked commitment transaction P 
# # # # # # # #

secret_rev_P = hash256("Hey! This is P, and this is my revocation secret".encode("utf-8").hex()) 
secret_rev_V = hash256("Hey! This is V, and this is my revocation secret".encode("utf-8").hex()) 

#print("")
#print("Rev Key P: ", secret_rev_P)
#print("Rev Key V: ", secret_rev_V)
#print("")

# P is owner and V is punisher. Secret_rev is from P (V knows it)
ct_P_locked = txs.get_ALBA_ct(TxInput('da09f9ac4c16a0f988350bca3243c9e3b6b7f6b8c471db7c49c50de2cb2b3eeb', 0), id_P, id_V, secret_rev_P, secret_rev_V, 9000, 9000, 420, l=True, bothsigs=False, timelock=0x2, locked=False)

ct_V_locked = txs.get_standard_ct(TxInput('da09f9ac4c16a0f988350bca3243c9e3b6b7f6b8c471db7c49c50de2cb2b3eeb', 0), id_P, id_V, secret_rev_V, 9000, 9000, 420, l=False, bothsigs=False, timelock=0x2, locked=True)

ct_P_unlocked = txs.get_ALBA_ct(TxInput('da09f9ac4c16a0f988350bca3243c9e3b6b7f6b8c471db7c49c50de2cb2b3eeb', 0), id_P, id_V, secret_rev_P, secret_rev_V, 9000, 9000, 420, l=True, bothsigs=False, timelock=0x2, locked=False)

ct_V_unlocked = txs.get_standard_ct(TxInput('da09f9ac4c16a0f988350bca3243c9e3b6b7f6b8c471db7c49c50de2cb2b3eeb', 0), id_P, id_V, secret_rev_V, 9000, 9000, 420, l=False, bothsigs=False, timelock=0x2, locked=False)

print("")
print("Comm TX P locked: ", ct_P_locked.serialize())
print("")
print("Comm TX V locked: ", ct_V_locked.serialize())
print("")
print("Comm TX P unlocked: ", ct_P_unlocked.serialize()) 
print("")
print("Comm TX V unlocked: ", ct_V_unlocked.serialize())

######### Useful Websites #########

# Breakdown Bitcoin Raw Transaction: https://rsbondi.github.io/btc-adventure/
# Bitcoin transactino decoder: https://live.blockcypher.com/btc/decodetx/
# Blockstream testnet explorer: https://blockstream.info/testnet/