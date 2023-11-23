from bitcoinutils.transactions import Transaction, TxOutput, TxInput, Sequence, TYPE_RELATIVE_TIMELOCK, TYPE_ABSOLUTE_TIMELOCK
#from transactions import Transaction, TxOutput, TxInput, Sequence, TYPE_RELATIVE_TIMELOCK, TYPE_ABSOLUTE_TIMELOCK

from bitcoinutils.script import Script
from identity import Id
import init
import scripts
import consts

init.init_network()

### Transactions for lightning

def get_standard_ct(tx_in: TxInput, id_l: Id, id_r: Id, hashed_secret, val_l: int, val_r: int, fee: int, l: bool, bothsigs: bool, timelock, locked: bool) -> Transaction:
    if l:
        tx_out0 = TxOutput(int(val_l-fee/2), scripts.get_script_lightning_locked(id_l, id_r, hashed_secret, timelock)) # output to l
        tx_out1 = TxOutput(int(val_r-fee/2), id_r.p2pkh) # output to r
    else:
        tx_out0 = TxOutput(int(val_r-fee/2), scripts.get_script_lightning_locked(id_r, id_l, hashed_secret, timelock)) # output to r
        tx_out1 = TxOutput(int(val_l-fee/2), id_l.p2pkh) # output to l

    if locked:
        tx = Transaction([tx_in], [tx_out0, tx_out1], "f0b78865")
    else:
        tx = Transaction([tx_in], [tx_out0, tx_out1])

    scriptFToutput = scripts.get_script_ft_output(id_l, id_r)

    if bothsigs:
        sig_l = id_l.sk.sign_input(tx, 0, scriptFToutput)
        sig_r = id_r.sk.sign_input(tx, 0, scriptFToutput)
        tx_in.script_sig = Script([sig_r, sig_l])
    else:
        if l:
            #sig_l = id_l.sk.sign_input(tx, 0, scriptFToutput)
            sig_r = id_r.sk.sign_input(tx, 0, scriptFToutput)
            tx_in.script_sig = Script([sig_r])
        else:
            sig_l = id_l.sk.sign_input(tx, 0, scriptFToutput)
            #sig_r = id_r.sk.sign_input(tx, 0, scriptFToutput)
            tx_in.script_sig = Script([sig_l])

    #sig_l = id_l.sk.sign_input(tx, 0, scriptFToutput)
    #sig_r = id_r.sk.sign_input(tx, 0, scriptFToutput)

    #tx_in.script_sig = Script([sig_r, sig_l])
    #tx_in.script_sig = Script([sig_l])

    return tx

def get_ALBA_ct(tx_in: TxInput, id_l: Id, id_r: Id, hashed_secret, opreturn_val, val_l: int, val_r: int, fee: int, l: bool, bothsigs: bool, timelock, locked: bool) -> Transaction:
    if l: #ct_prover, has id and secret_V in opreturn output
        tx_out0 = TxOutput(int(val_l-fee/2), scripts.get_script_lightning_locked(id_l, id_r, hashed_secret, timelock)) # output to l
        tx_out1 = TxOutput(int(val_r-fee/2), id_r.p2pkh) # output to r
        op_return_script_id =  Script(['OP_RETURN', 'OP_1']) #omit id for checking valid latest state
        op_return_script_revSec =  Script(['OP_RETURN', opreturn_val])
        tx_out2 = TxOutput(0, op_return_script_revSec)
        tx_out3 = TxOutput(0, op_return_script_id) 

        if locked:
            tx = Transaction([tx_in], [tx_out0, tx_out1, tx_out2], "f0b78865") # timelock is Sun Dec 03 2023 12:53:20 GMT+0000 -> I had to flip bytes: UNIX timestamp is 1701608000 -> 656C7A40 -> 407a6c65
                                                                               # timelock Sat Oct 28 2023 22:00:00 GMT+0000 is 653D8460 in hex, but I need to flip bytes and it becomes: 60843d65
                                                                               # timelock Tue Dec 19 2023 23:00:00 GMT+0000 is 65822070 in hex, but I need to flip bytes and it becomes: 70208265
                                                                               # Sun Dec 24 2023 23:00:00 GMT+0000: 6588B7F0 -> f0b78865
        else:
            tx = Transaction([tx_in], [tx_out0, tx_out1, tx_out2])

    else: #ct_verifier, locked with secret_V
        tx_out0 = TxOutput(int(val_r-fee/2), scripts.get_script_lightning_locked(id_r, id_l, hashed_secret, timelock)) # output to r
        tx_out1 = TxOutput(int(val_l-fee/2), id_l.p2pkh) # output to l

        if locked:
            tx = Transaction([tx_in], [tx_out0, tx_out1], "f0b78865")
        else:
            tx = Transaction([tx_in], [tx_out0, tx_out1])
    
    #print("Tx to be (hashed?) and signed: ", tx.serialize())

    scriptFToutput = scripts.get_script_ft_output(id_l, id_r)

    if bothsigs:
        sig_l = id_l.sk.sign_input(tx, 0, scriptFToutput)
        sig_r = id_r.sk.sign_input(tx, 0, scriptFToutput)
        tx_in.script_sig = Script([sig_r, sig_l])
    else:
        if l:
            #sig_l = id_l.sk.sign_input(tx, 0, scriptFToutput)
            sig_r = id_r.sk.sign_input(tx, 0, scriptFToutput)
            tx_in.script_sig = Script([sig_r])
        else:
            sig_l = id_l.sk.sign_input(tx, 0, scriptFToutput)
            #sig_r = id_r.sk.sign_input(tx, 0, scriptFToutput)
            tx_in.script_sig = Script([sig_l])

    #tx_in.script_sig = Script([sig_r, sig_l])
    #tx_in.script_sig = Script([sig_r]) #only signed by the counterparty

    return tx

def get_standard_ct_spend(tx_in: TxInput, payee: Id, script_ct: Script, val: int, fee: int)-> Transaction:

    tx_out = TxOutput(val-fee, payee.p2pkh)
    tx = Transaction([tx_in], [tx_out])
    
    sig = payee.sk.sign_input(tx, 0 , Script(script_ct))

    tx_in.script_sig = Script([sig])
    
    return tx

def get_standard_ct_punish(tx_in: TxInput, payee: Id, script_ct: Script, secret, val: int, fee: int)-> Transaction:

    tx_out = TxOutput(val-fee, payee.p2pkh)
    tx = Transaction([tx_in], [tx_out])
    
    sig = payee.sk.sign_input(tx, 0 , Script(script_ct))

    tx_in.script_sig = Script([secret, sig])
    
    return tx

### Generalized construction

def get_gen_ct_tx(tx_in: TxInput, id_l: Id, id_r: Id, id_as_l: Id, hashed_secret_rev_l, id_as_r: Id, hashed_secret_rev_r, val: int, fee: int, timelock: int) -> Transaction:
    timelock = 0x2
    tx_out = TxOutput(val-fee, scripts.get_script_split(id_l, id_r, id_as_l, hashed_secret_rev_l, id_as_r, hashed_secret_rev_r, timelock))
    tx = Transaction([tx_in], [tx_out])

    scriptFToutput = scripts.get_script_ft_output(id_l, id_r)

    sig_l = id_l.sk.sign_input(tx, 0 , scriptFToutput)
    sig_r = id_r.sk.sign_input(tx, 0 , scriptFToutput)

    tx_in.script_sig = Script([sig_r, sig_l])

    return tx

def get_gen_split_tx(tx_in: TxInput, id_l: Id, id_r: Id, script: Script, val_l: int, val_r, fee: int) -> Transaction:
    tx_out0 = TxOutput(int(val_l-0.5*fee), id_l.p2pkh)
    tx_out1 = TxOutput(int(val_r-0.5*fee), id_r.p2pkh)
    tx = Transaction([tx_in], [tx_out0, tx_out1])

    sig_l = id_l.sk.sign_input(tx, 0, Script(script))
    sig_r = id_r.sk.sign_input(tx, 0, Script(script))

    tx_in.script_sig = Script([sig_r, sig_l])

    return tx

def get_gen_punish_tx(tx_in: TxInput, payee: Id, script: Script, id_as: Id, secret_rev, val: int, fee: int, l: bool) -> Transaction:
    tx_out = TxOutput(val-fee, payee.p2pkh)
    tx = Transaction([tx_in], [tx_out])

    sig = payee.sk.sign_input(tx, 0, Script(script))
    sig_as = id_as.sk.sign_input(tx, 0, Script(script))

    if l:
        tx_in.script_sig = Script([secret_rev, sig_as, 0x0, sig])
    else:
        tx_in.script_sig = Script([secret_rev, sig_as, sig, 0x0])

    return tx

### Test HTLC construction (just for measuring)

def get_htlc(tx_in: TxInput, id_l: Id, id_r: Id, secret, hashed_secret, val_l: int, val_r: int, fee: int, l: bool, timelock) -> Transaction:
    tx_out = TxOutput(int(val_l-fee/2), scripts.get_script_lightning_locked(id_l, id_r, hashed_secret, timelock)) # output to l

    tx = Transaction([tx_in], [tx_out])

    scriptFToutput = scripts.get_script_ft_output(id_l, id_r)

    sig = id_l.sk.sign_input(tx, 0, scriptFToutput) # referenced tx is ft

    tx_in.script_sig = Script([sig, secret])

    return tx

def get_htlc_ct(tx_in: TxInput, id_l: Id, id_r: Id, hashed_secret, hashed_secret2, val_l: int, val_r: int, x, fee: int, l: bool, timelock) -> Transaction:
    if l:
        tx_out0 = TxOutput(int(val_l-fee/2), scripts.get_script_lightning_locked(id_l, id_r, hashed_secret, timelock)) # output to l
        tx_out1 = TxOutput(int(val_l-fee/2), scripts.get_htlc_script(id_l, id_r, hashed_secret, hashed_secret2, timelock)) # HTLC output
        tx_out2 = TxOutput(int(val_r-fee/2), id_r.p2pkh) # output to r
    else:
        tx_out0 = TxOutput(int(val_r-fee/2), scripts.get_script_lightning_locked(id_r, id_l, hashed_secret, timelock)) # output to r
        tx_out1 = TxOutput(int(val_l-fee/2), scripts.get_htlc_script(id_l, id_r, hashed_secret, hashed_secret2, timelock)) # HTLC output
        tx_out2 = TxOutput(int(val_l-fee/2), id_l.p2pkh) # output to l

    tx = Transaction([tx_in], [tx_out0, tx_out1, tx_out2])

    scriptFToutput = scripts.get_script_ft_output(id_l, id_r)

    sig_l = id_l.sk.sign_input(tx, 0, scriptFToutput)
    sig_r = id_r.sk.sign_input(tx, 0, scriptFToutput)

    tx_in.script_sig = Script([sig_r, sig_l])

    return tx