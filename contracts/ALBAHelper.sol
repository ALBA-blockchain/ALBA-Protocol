pragma solidity ^0.8.9;
pragma experimental ABIEncoderV2;

import "hardhat/console.sol";
import "./ParseBTCLib.sol";
import "./BytesLib.sol";
import "./BTCUtils.sol";
import "./ECDSA.sol";


library ALBAHelper {

    function checkTxAreWellFormed(bytes memory TxP, bytes memory TxV, bytes memory fundingTx_script, bytes32 fundingTxId) 
        internal pure returns (ParseBTCLib.HTLCData[2] memory, 
                               ParseBTCLib.P2PKHData[2] memory,
                               ParseBTCLib.OpReturnData memory) {

        // check transactions are well formed
        ParseBTCLib.HTLCData[2] memory lightningHTLC;
        ParseBTCLib.P2PKHData[2] memory p2pkh; 
        ParseBTCLib.OpReturnData memory opreturn;
        (lightningHTLC[0], p2pkh[0], opreturn) = ParseBTCLib.getOutputsDataLNB(TxP); //note: the p2pkh_P is the p2pkh belonging in P's commitment transaction, but holds the public key of V
        (lightningHTLC[1], p2pkh[1]) = ParseBTCLib.getOutputsDataLN(TxV); //note: the p2pkh_V is the p2pkh belonging in V's commitment transaction, but holds the public key of P

        require(opreturn.data == lightningHTLC[1].rev_secret, "P's commitment transaction does not hardcode V's revocation key");
        require(p2pkh[0].value == lightningHTLC[1].value, "Amount mismatch between p2pkh of P and lightning HTLC of V");
        require(lightningHTLC[0].value == p2pkh[1].value, "Amount mismatch between p2pkh of V and lightning HTLC of P");

        (bytes memory pk1, bytes memory pk2) = ParseBTCLib.extractCompressedPK(fundingTx_script);
        require(sha256(BTCUtils.hash160(pk2)) == sha256(abi.encodePacked(p2pkh[0].pkhash)), "The p2pkh in P's unlocked commitment transaction does not correspond to Verifier's one");
        require(sha256(BTCUtils.hash160(pk1)) == sha256(abi.encodePacked(p2pkh[1].pkhash)), "The p2pkh in V's unlocked commitment transaction does not correspond to Prover's one");        

        // check transactions spend the funding transaction 
        require(ParseBTCLib.getInputsData(TxP).txid == fundingTxId, "CTxP does not spend funding Tx");
        require(ParseBTCLib.getInputsData(TxV).txid == fundingTxId, "CTxV does not spend funding Tx");

        return (lightningHTLC, p2pkh, opreturn);

    }

    function getRevSecret(bytes memory Tx) internal pure returns (bytes32) {

        ParseBTCLib.HTLCData memory lightningHTLC;
        ParseBTCLib.P2PKHData memory p2pkh; 
        ParseBTCLib.OpReturnData memory opreturn;
        (lightningHTLC, p2pkh, opreturn) = ParseBTCLib.getOutputsDataLNB(Tx); 
        
        return lightningHTLC.rev_secret;

    }

    function checkSignatures(bytes memory TxP, bytes memory TxV, bytes memory fundingTx_script, bytes memory sighash, bytes memory pkProver_Uncompressed, bytes memory pkVerifier_Uncompressed) internal pure returns (bool) {

        //retrieve signatures
        ParseBTCLib.Signature[2] memory sig;
        sig[1] = ParseBTCLib.getSignature(TxP); // sig V
        sig[0] = ParseBTCLib.getSignature(TxV); // sig P

        //verify signatures
        bytes32[2] memory digest;
        digest[0] =  ParseBTCLib.getTxDigest(TxP, fundingTx_script, sighash); // digest of commitment transaction of P      
        // https://bitcointalk.org/index.php?topic=5249677.0
        // recid used to compute v is not necessary: just cycle through all the possible coordinate pairs and check if any of them match the signature. The recid just speeds up  verification.
        // TODO: to determine parity, one can use the (unpacked) x in the verifyBTCSignature
        require((sha256(ParseBTCLib.verifyBTCSignature(uint256(digest[0]), uint8(sig[1].v), BytesLib.toUint256(sig[1].r,0), BytesLib.toUint256(sig[1].s,0))) == sha256(pkVerifier_Uncompressed)
        || (sha256(ParseBTCLib.verifyBTCSignature(uint256(digest[0]), uint8(sig[1].v+1), BytesLib.toUint256(sig[1].r,0), BytesLib.toUint256(sig[1].s,0))) == sha256(pkVerifier_Uncompressed))
        || sha256(ParseBTCLib.verifyBTCSignature(uint256(digest[0]), uint8(sig[1].v+2), BytesLib.toUint256(sig[1].r,0), BytesLib.toUint256(sig[1].s,0))) == sha256(pkVerifier_Uncompressed)
        || sha256(ParseBTCLib.verifyBTCSignature(uint256(digest[0]), uint8(sig[1].v+3), BytesLib.toUint256(sig[1].r,0), BytesLib.toUint256(sig[1].s,0))) == sha256(pkVerifier_Uncompressed)
        ), "Invalid signature of V over CTxP"); 

        digest[1] = ParseBTCLib.getTxDigest(TxV, fundingTx_script, sighash); // the last argument is the sighash, which in this case is SIGHASH_ALL
        require((sha256(ParseBTCLib.verifyBTCSignature(uint256(digest[1]), uint8(sig[0].v), BytesLib.toUint256(sig[0].r,0), BytesLib.toUint256(sig[0].s,0))) == sha256(pkProver_Uncompressed)
        || sha256(ParseBTCLib.verifyBTCSignature(uint256(digest[1]), uint8(sig[0].v+1), BytesLib.toUint256(sig[0].r,0), BytesLib.toUint256(sig[0].s,0))) == sha256(pkProver_Uncompressed)
        || sha256(ParseBTCLib.verifyBTCSignature(uint256(digest[1]), uint8(sig[0].v+2), BytesLib.toUint256(sig[0].r,0), BytesLib.toUint256(sig[0].s,0))) == sha256(pkProver_Uncompressed)
        || sha256(ParseBTCLib.verifyBTCSignature(uint256(digest[1]), uint8(sig[0].v+3), BytesLib.toUint256(sig[0].r,0), BytesLib.toUint256(sig[0].s,0))) == sha256(pkProver_Uncompressed)
        ), "Invalid signature of P over CTxV");

        return true;

    }

    function checkSignature(bytes memory Tx, bytes memory fundingTx_script, bytes memory sighash, bytes memory pk_Uncompressed) internal pure returns (bool) {

        // check it has valid signature of V
            ParseBTCLib.Signature memory sigV = ParseBTCLib.getSignature(Tx); 
            bytes32 digest = ParseBTCLib.getTxDigest(Tx, fundingTx_script, sighash);
            require((sha256(ParseBTCLib.verifyBTCSignature(uint256(digest), uint8(sigV.v), BytesLib.toUint256(sigV.r,0), BytesLib.toUint256(sigV.s,0))) == sha256(pk_Uncompressed)
            || sha256(ParseBTCLib.verifyBTCSignature(uint256(digest), uint8(sigV.v+1), BytesLib.toUint256(sigV.r,0), BytesLib.toUint256(sigV.s,0))) == sha256(pk_Uncompressed)
            || sha256(ParseBTCLib.verifyBTCSignature(uint256(digest), uint8(sigV.v+2), BytesLib.toUint256(sigV.r,0), BytesLib.toUint256(sigV.s,0))) == sha256(pk_Uncompressed)
            || sha256(ParseBTCLib.verifyBTCSignature(uint256(digest), uint8(sigV.v+3), BytesLib.toUint256(sigV.r,0), BytesLib.toUint256(sigV.s,0))) == sha256(pk_Uncompressed)), 
            "Invalid signature of V over CTxP"); 

        return true;

    }

    function checkSignaturesEcrecover(bytes memory TxP, bytes memory TxV, bytes memory fundingTx_script, bytes memory sighash, bytes memory pkProver_Uncompressed, bytes memory pkVerifier_Uncompressed) internal pure returns (bool) {

        //retrieve signatures
        ParseBTCLib.Signature[2] memory sig;
        sig[1] = ParseBTCLib.getSignature(TxP); // sig V
        sig[0] = ParseBTCLib.getSignature(TxV); // sig P

        //verify signatures
        bytes32[2] memory digest;
        digest[0] =  ParseBTCLib.getTxDigest(TxP, fundingTx_script, sighash); // digest of commitment transaction of P      
        // https://bitcointalk.org/index.php?topic=5249677.0
        // recid used to compute v is not necessary: just cycle through all the possible coordinate pairs and check if any of them match the signature. The recid just speeds up  verification.
        // TODO: to determine parity, one can use the (unpacked) x in the verifyBTCSignature
        address ethAddressV = ecrecover(digest[0], sig[1].v, bytes32(sig[1].r), bytes32(sig[1].s));
        address pkToAddressV = address(bytes20(BytesLib.slice(abi.encodePacked(keccak256(pkVerifier_Uncompressed)), 12, 20)));
        if (ethAddressV != pkToAddressV) {
            ethAddressV = ecrecover(digest[0], sig[1].v+1, bytes32(sig[1].r), bytes32(sig[1].s));
            require(ethAddressV == pkToAddressV, "Invalid signature of V over CTxP");
        }

        digest[1] = ParseBTCLib.getTxDigest(TxV, fundingTx_script, sighash); // the last argument is the sighash, which in this case is SIGHASH_ALL
        address ethAddressP = ecrecover(digest[1], sig[0].v, bytes32(sig[0].r), bytes32(sig[0].s));
        address pkToAddressP = address(bytes20(BytesLib.slice(abi.encodePacked(keccak256(pkProver_Uncompressed)), 12, 20)));
        if (ethAddressP != pkToAddressP) {
            ethAddressP = ecrecover(digest[1], sig[0].v+1, bytes32(sig[0].r), bytes32(sig[0].s));
            require(ethAddressP == pkToAddressP, "Invalid signature of P over CTxV");
        }

        return true;

    }


    function checkSignatureEcrecover(bytes memory Tx, bytes memory fundingTx_script, bytes memory sighash, bytes memory pk) internal pure {

        // check it has valid signature of V
        ParseBTCLib.Signature memory sigV = ParseBTCLib.getSignature(Tx); 
        bytes32 digest = ParseBTCLib.getTxDigest(Tx, fundingTx_script, sighash);

        address ethAddress = ecrecover(digest, sigV.v, bytes32(sigV.r), bytes32(sigV.s));
        address pkToAddress = address(bytes20(BytesLib.slice(abi.encodePacked(keccak256(pk)), 12, 20)));
        if (ethAddress != pkToAddress) {
            ethAddress = ecrecover(digest, sigV.v+1, bytes32(sigV.r), bytes32(sigV.s));
            require(ethAddress == pkToAddress, "Invalid signature");
        }
    }

}
