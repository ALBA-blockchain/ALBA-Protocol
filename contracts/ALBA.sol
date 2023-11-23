pragma solidity ^0.8.9;
//pragma experimental ABIEncoderV2;

import "hardhat/console.sol";
import "./ParseBTCLib.sol";
import "./BytesLib.sol";
import "./BTCUtils.sol";
import "./ECDSA.sol";
import "./ALBAHelper.sol";
import "./SchnorrN.sol";

// This contract is used by Prover P and verifier V to verify on Ethereum the current state of their Lightning payment channel 

contract ALBA {

    event stateEvent(string label, bool status);
    event lockEvent(string label, address addr, uint amount);

    // define global variables for this contract instance (setup phase)
    struct ALBAParam {
        bytes32 fundTxId;
        bytes fundTxScript;
        bytes4 fundTxIndx;
        bytes sighash;
        bytes pkPUncompr; 
        bytes pkVUncompr;
        uint256 timelock; //timelock is 1701817200, i.e., Tue Dec 05 2023 23:00:00 GMT+0000. 
        uint256 timelockDisp; //relative timelock 
        uint256 balDistr; 
    }

    struct ALBAState {
        bool coinsLocked;
        bool setupDone;
        bool proofSubmitted;
        bool disputeOpened;
        bool disputeClosedP;
        bool disputeClosedV;
    }

    struct PaymentChannel {
        uint balP; // this is the balance in the payment channel
        uint balV; // this is the balance in the payment channel
        bytes32 rKey; // revocation key
    }

    ALBAParam public bridge;
    ALBAState public state;    
    PaymentChannel public paymentChan;

    mapping(address => uint256) initBalEth;

    address prover;
    address verifier;
    uint256 totalSupply;

    constructor(address _prover, address _verifier) {
        prover = _prover; 
        verifier = _verifier; 
    } 

    // this function allows protocol parties to lock funds in the contract
    receive() external payable {

        // React to receiving ether
        initBalEth[msg.sender] = msg.value; 
        totalSupply = totalSupply + msg.value;
        state.coinsLocked = true;
        emit lockEvent("Coins locked!", msg.sender, msg.value);
    
    } 

    function setup(bytes32 fundTxId, 
                   bytes memory fundTxScript, 
                   bytes4 fundTxIndx, 
                   bytes memory sighash,
                   bytes memory pkPUncompr, 
                   bytes memory pkVUncompr, 
                   uint256 timelock, 
                   uint256 timelockDisp, 
                   bytes memory sigP, 
                   bytes memory sigV) external {
        
        // populate protocol specifics
        bridge.fundTxId = fundTxId;
        bridge.fundTxScript = fundTxScript;
        bridge.fundTxIndx = fundTxIndx;
        bridge.sighash = sighash;
        bridge.pkPUncompr = pkPUncompr;
        bridge.pkVUncompr = pkVUncompr;
        bridge.timelock = timelock;
        bridge.timelockDisp = timelockDisp;

        bridge.balDistr = 7; // TODO for the future: make it dynamic

        // verify signatures over setup data
        bytes memory message = bytes.concat(BytesLib.toBytes(bridge.fundTxId), bridge.fundTxScript, BytesLib.toBytesNew(bridge.fundTxIndx), bridge.sighash, bridge.pkPUncompr, bridge.pkVUncompr, BytesLib.uint256ToBytes(bridge.timelock), BytesLib.uint256ToBytes(bridge.timelockDisp));
        require(prover == ECDSA.recover(sha256(message), abi.encodePacked(sigP)) && verifier == ECDSA.recover(sha256(message), abi.encodePacked(sigV)), "Invalid signatures over setup data");

        // populate state variables
        state.proofSubmitted = false;
        state.disputeOpened = false;
        state.disputeClosedP = false;
        state.disputeClosedV = false;
        state.setupDone = true;
    }

    function submitProof(bytes memory CT_P_unlocked,                    
                         bytes memory CT_V_unlocked) external {

        // check that current time is smaller than the timeout defined in Setup, and check proof has not yet been submitted, nor dispute raised
        if (block.timestamp < bridge.timelock && (state.coinsLocked == true && 
                                                  state.setupDone == true && 
                                                  state.proofSubmitted == false && 
                                                  state.disputeOpened == false)) {

            // check transactions are not locked
            require(ParseBTCLib.getTimelock(CT_P_unlocked) == bytes4(0), "CTxP locked");
            require(ParseBTCLib.getTimelock(CT_V_unlocked) == bytes4(0), "CTxV locked");

            // check transactions are well formed
            ParseBTCLib.HTLCData[2] memory htlc;
            ParseBTCLib.P2PKHData[2] memory p2pkh; 
            ParseBTCLib.OpReturnData memory opreturn;
            (htlc, p2pkh, opreturn) = ALBAHelper.checkTxAreWellFormed(CT_P_unlocked, CT_V_unlocked, bridge.fundTxScript, bridge.fundTxId);

            ALBAHelper.checkSignaturesEcrecover(CT_P_unlocked, CT_V_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkPUncompr, bridge.pkVUncompr);         

            // Check on the channel balance: e.g., require the balance of P is higher than X, with X = 10 in this example
            require(htlc[0].value > 10, "Prover does not have a sufficient amount of coins");
    
            // update state of the protocol
            state.proofSubmitted = true;

            emit stateEvent("Proof successfully verified", state.proofSubmitted);

        } else {

            emit stateEvent("Proof verification failed", state.proofSubmitted);

        } 
    }

    function optimisticSubmitProof(bytes memory sigP, 
                             bytes memory sigV, uint256 seqNumber) external {

        //string memory label = "proofSubmitted";
        bytes32 message = sha256(bytes.concat(BytesLib.uint256ToBytes(seqNumber), abi.encodePacked("proofSubmitted"), abi.encodePacked(true)));

        // check that P and V signed a message of the form (sn, proofSubmitted, true), where they acknowledge to distribute funds
        if (block.timestamp < bridge.timelock && state.coinsLocked == true 
                                              && state.setupDone == true 
                                              && state.proofSubmitted == false 
                                              && state.disputeOpened == false
                                              && prover == ECDSA.recover(message, abi.encodePacked(sigP)) 
                                              && verifier == ECDSA.recover(message, abi.encodePacked(sigV))) {

            // update state of the protocol
            state.proofSubmitted = true;

            emit stateEvent("Proof optimistically verified", state.proofSubmitted);

        } else {

            emit stateEvent("Proof verification failed", state.proofSubmitted);

        }   
    }

    function dispute(bytes memory CT_P_locked, 
                     bytes memory CT_V_unlocked) external {

        // check that current time is smaller than the timeout defined in Setup, and check proof has not yet been submitted, nor dispute raised
        if (block.timestamp < bridge.timelock && (state.coinsLocked == true && 
                                                  state.setupDone == true && 
                                                  state.proofSubmitted == false && 
                                                  state.disputeOpened == false)) {
            
            // check commitment transaction of P is locked and commitment transaction of V is unlocked
            require(ParseBTCLib.getTxTimelock(CT_P_locked) > bridge.timelock + bridge.timelockDisp, "CTxP is unlocked or its timelocked is smaller than/equal to T + T_rel"); 
            require(ParseBTCLib.getTxTimelock(CT_V_unlocked) == uint32(0), "CTxV is locked"); 

            // check transactions are well formed
            ParseBTCLib.HTLCData[2] memory htlc;
            ParseBTCLib.P2PKHData[2] memory p2pkh; 
            ParseBTCLib.OpReturnData memory opreturn;
            (htlc, p2pkh, opreturn) = ALBAHelper.checkTxAreWellFormed(CT_P_locked, CT_V_unlocked, bridge.fundTxScript, bridge.fundTxId);

            require(ALBAHelper.checkSignaturesEcrecover(CT_P_locked, CT_V_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkPUncompr, bridge.pkVUncompr) == true, "Invalid signatures");   

            // Check on the channel balance: e.g., require the balance of P is higher than X, with X = 10 in this example
            require(htlc[0].value > 10, "No sufficient amount of coins");

            // store balances
            paymentChan.balP = htlc[0].value;
            paymentChan.balV = htlc[1].value;
            // store also the revocation key of P for resolveInvalidDispute
            paymentChan.rKey = ALBAHelper.getRevSecret(CT_P_locked);
    
            // update state of the protocol
            state.disputeOpened = true;

            emit stateEvent("Dispute opened", state.disputeOpened); 

        } else {

            emit stateEvent("Failed to open dispute", state.disputeOpened);
        } 
    }

    // resolve valid dispute raised by P: V submits the unlocked version of the transaction
    function resolveValidDispute(bytes memory CT_P_unlocked) external {

        if (block.timestamp < (bridge.timelock + bridge.timelockDisp) && (state.coinsLocked == true && state.setupDone == true && state.proofSubmitted == false && state.disputeOpened == true)) {

            // check transaction is not locked
            require(ParseBTCLib.getTimelock(CT_P_unlocked) == bytes4(0), "CTxP locked");

            //check transaction spends the funding transaction
            require(ParseBTCLib.getInputsData(CT_P_unlocked).txid == bridge.fundTxId, "CTxP does not spend funding Tx");

            // check balance correctness
            ParseBTCLib.HTLCData memory htlc;
            ParseBTCLib.P2PKHData memory p2pkh; 
            ParseBTCLib.OpReturnData memory opreturn;
            (htlc, p2pkh, opreturn) = ParseBTCLib.getOutputsDataLNB(CT_P_unlocked); 
            require(htlc.value == paymentChan.balP, "The value in the HTLC does not corrispond to the value in the HTLC of P's locked transaction");
            require(p2pkh.value == paymentChan.balV, "The value in the p2pkh does not corrispond to the value in the HTLC of V's unlocked transaction");

            //check signature
            ALBAHelper.checkSignatureEcrecover(CT_P_unlocked, bridge.fundTxScript, bridge.sighash, bridge.pkVUncompr);    
        
            // update state of the protocol
            state.disputeClosedP = true;

            emit stateEvent("Valid Dispute resolved", state.disputeClosedP);

        } else {

            emit stateEvent("Valid Dispute unresolved", state.disputeClosedP);
        } 
    }

    // resolve invalid dispute raised by P: V provides the revocation secret for that proves P opened the dispute with an old state
    function resolveInvalidDispute(string memory revSecret) external {

        if (block.timestamp < (bridge.timelock + bridge.timelockDisp) 
            && (state.coinsLocked == true  && state.setupDone == true && state.proofSubmitted == false && state.disputeOpened == true)
            && paymentChan.rKey == sha256(abi.encodePacked(sha256(bytes(revSecret))))) {

            // update state of the protocol
            state.disputeClosedV = true;

            emit stateEvent("Invalid Dispute resolved", state.disputeClosedV);

        } else {

            emit stateEvent("Invalid Dispute unresolved", state.disputeClosedV);
        } 
       
    }

    function settle() external payable {

        if (state.proofSubmitted == true || (state.disputeOpened == true && state.disputeClosedP == true)) {

            // distribute funds in the contract according to mapping
            (bool sentP, ) = prover.call{value: (totalSupply * (bridge.balDistr / 100))}("");
            require(sentP, "Failed to send ETH");
            (bool sentV, ) = verifier.call{value: (totalSupply * (1 - bridge.balDistr / 100))}("");
            require(sentV, "Failed to send ETH");

            emit stateEvent("Valid proof submitted and funds distributed", true);

        } else if (state.disputeOpened == true && (state.disputeClosedP == false && state.disputeClosedV == false)) {

            // dispute has not been closed: give all funds in the contract to prover
            (bool sentP, ) = prover.call{value: totalSupply}("");
            require(sentP, "Failed to send ETH");

            emit stateEvent("All funds given to P", true);

        } else if (state.disputeOpened == true && state.disputeClosedV == true ) {

            // dispute was opened with an old state: give all funds in the contract to verifier
            (bool sentV, ) = verifier.call{value: totalSupply}("");
            require(sentV, "Failed to send ETH");

            emit stateEvent("All funds given to V", true);

        } else if (state.coinsLocked == true && state.setupDone == false) {

            // nobody submitted nothing: distribute funds according to inital state (give back to P and V the amount they contributed with)
            (bool sentP, ) = prover.call{value: initBalEth[prover]}("");
            require(sentP, "Failed to send ETH");
            (bool sentV, ) = verifier.call{value: initBalEth[verifier]}("");
            require(sentV, "Failed to send ETH");

            emit stateEvent("Funds distributed", true);

        }
    } 

}
