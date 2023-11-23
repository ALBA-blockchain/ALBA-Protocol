pragma solidity ^0.8.9;

/** @title CheckBitcoinSigs */
/** @author Summa (https://summa.one) */

//import {TypedMemView} from "@summa-tx/memview.sol/contracts/TypedMemView.sol";
import "./TypedMemView.sol";
import "hardhat/console.sol";
import "./BTCUtils.sol";

library CheckBitcoinSigs {

    using TypedMemView for bytes29;
    using TypedMemView for bytes;

    /// @notice          Derives an Ethereum Account address from a pubkey
    /// @dev             The address is the last 20 bytes of the keccak256 of the address
    /// @param _pubkey   The public key X & Y. Unprefixed, as a 64-byte array
    /// @return          The account address
    function accountFromPubkey(bytes memory _pubkey) internal pure returns (address) {
        require(_pubkey.length == 64, "Pubkey must be 64-byte raw, uncompressed key.");

        bytes32 _digest = _pubkey.ref(0).keccak();
        return address((uint160(uint256(_digest))));
    }

    function accountFromPubkey_mod(bytes memory _pubkey) internal pure returns (bytes20) {
        require(_pubkey.length == 64, "Pubkey must be 64-byte raw, uncompressed key.");

        //bytes32 _digest = _pubkey.ref(0).keccak();
        bytes20 _digest = bytes20(BTCUtils.hash160(_pubkey));
        return _digest;
        //return address((uint160(uint256(_digest))));
    }

    /// @notice          Calculates the p2wpkh output script of a pubkey
    /// @dev             Compresses keys to 33 bytes as required by Bitcoin wpkh
    /// @param _pubkey   The public key, compressed or uncompressed
    /// @return          The p2wkph output script
    function p2wpkhFromPubkey(bytes memory _pubkey) internal view returns (bytes memory) {
        bytes29 _pubkeyView = _pubkey.ref(0);

        bytes20 _digest;
        if (_pubkey.length == 33) {_digest = _pubkeyView.hash160();}
        else if (_pubkey.length == 64) {
            // This is less memory efficient than it ought to be
            // But we immediately deallocate it, so it's usually no issue
            uint8 prefix = uint8(_pubkey[_pubkey.length - 1]) % 2 + 2;
            bytes memory _x = _pubkeyView.prefix(32, 0).clone();
            bytes memory _compressed = abi.encodePacked(prefix, _x);
            _digest = _compressed.ref(0).hash160();
            // Deallocate memory
            assembly {
                // solium-disable-previous-line security/no-inline-assembly
                mstore(0x40, _x)
            }
        }

        require(
            _digest != bytes20(0),
            "CheckBitcoinSigs/p2wpkhFromPubkey -- Invalid pubkey length. expected 64 or 33"
        );

        return abi.encodePacked(hex"0014", _digest);
    }

    /// @notice          checks a signed message's validity under a pubkey
    /// @dev             does this using ecrecover because Ethereum has no soul
    /// @param _pubkey   the public key to check (64 bytes)
    /// @param _digest   the message digest signed
    /// @param _v        the signature recovery value
    /// @param _r        the signature r value
    /// @param _s        the signature s value
    /// @return          true if signature is valid, else false
    function checkSig(
        bytes memory _pubkey,
        bytes32 _digest,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) internal pure returns (bool) {
        require(_pubkey.length == 64, "CheckBitcoinSigs/checkSig -- Requires uncompressed unprefixed pubkey");
        address _expected = address(accountFromPubkey(_pubkey));
        console.log("Expected address:", _expected);
        address _actual = ecrecover(_digest, _v, _r, _s);
        console.log("Actual address:  ", _actual);
        return _actual == _expected;
    }

    /// @notice                     checks a signed message against a bitcoin p2wpkh output script
    /// @dev                        does this my verifying the p2wpkh matches an ethereum account
    /// @param _p2wpkhOutputScript  the bitcoin output script
    /// @param _pubkey              the uncompressed, unprefixed public key to check
    /// @param _digest              the message digest signed
    /// @param _v                   the signature recovery value
    /// @param _r                   the signature r value
    /// @param _s                   the signature s value
    /// @return                     true if signature is valid, else false
    function checkBitcoinSig(
        bytes memory _p2wpkhOutputScript,
        bytes memory _pubkey,
        bytes32 _digest,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) internal view returns (bool) {
        require(_pubkey.length == 64, "CheckBitcoinSigs/checkBitcoinSig -- Requires uncompressed unprefixed pubkey");
        bool _isExpectedSigner = keccak256(p2wpkhFromPubkey(_pubkey)) == keccak256(_p2wpkhOutputScript);  // is it the expected signer?
        if (!_isExpectedSigner) {return false;}

        bool _sigResult = checkSig(_pubkey, _digest, _v, _r, _s);
        return _sigResult;
    }

    /// @notice             checks if a message is the sha256 preimage of a digest
    /// @dev                this is NOT the hash256!  this step is necessary for ECDSA security!
    /// @param _digest      the digest
    /// @param _candidate   the purported preimage
    /// @return             true if the preimage matches the digest, else false
    function isSha256Preimage(
        bytes memory _candidate,
        bytes32 _digest
    ) internal pure returns (bool) {
        return sha256(_candidate) == _digest;
    }

    /// @notice             checks if a message is the keccak256 preimage of a digest
    /// @dev                this step is necessary for ECDSA security!
    /// @param _digest      the digest
    /// @param _candidate   the purported preimage
    /// @return             true if the preimage matches the digest, else false
    function isKeccak256Preimage(
        bytes memory _candidate,
        bytes32 _digest
    ) internal pure returns (bool) {
        return keccak256(_candidate) == _digest;
    }

    /// @notice                 calculates the signature hash of a Bitcoin transaction with the provided details
    /// @dev                    documented in bip143. many values are hardcoded here
    /// @param _outpoint        the bitcoin UTXO id (32-byte txid + 4-byte output index)
    /// @param _inputPKH        the input pubkeyhash (hash160(sender_pubkey))
    /// @param _inputValue      the value of the input in satoshi
    /// @param _outputValue     the value of the output in satoshi
    /// @param _outputScript    the length-prefixed output script
    /// @return                 the double-sha256 (hash256) signature hash as defined by bip143
    function wpkhSpendSighash(
        bytes memory _outpoint,  // 36-byte UTXO id
        bytes20 _inputPKH,       // 20-byte hash160
        bytes8 _inputValue,      // 8-byte LE
        bytes8 _outputValue,     // 8-byte LE
        bytes memory _outputScript    // lenght-prefixed output script
    ) internal view returns (bytes32) {

        // Fixes elements to easily make a 1-in 1-out sighash digest
        // Does not support timelocks
        bytes memory _scriptCode = abi.encodePacked(
            hex"1976a914",  // length, dup, hash160, pkh_length
            _inputPKH,
            hex"88ac");  // equal, checksig
        bytes32 _hashOutputs = abi.encodePacked(
            _outputValue,  // 8-byte LE
            _outputScript).ref(0).hash256();
        bytes memory _sighashPreimage = abi.encodePacked(
            hex"01000000",  // version
            _outpoint.ref(0).hash256(),  // hashPrevouts
            hex"8cb9012517c817fead650287d61bdd9c68803b6bf9c64133dcab3e65b5a50cb9",  // hashSequence(00000000)
            _outpoint,  // outpoint
            _scriptCode,  // p2wpkh script code
            _inputValue,  // value of the input in 8-byte LE
            hex"00000000",  // input nSequence
            _hashOutputs,  // hash of the single output
            hex"00000000",  // nLockTime
            hex"01000000"  // SIGHASH_ALL
        );
        return _sighashPreimage.ref(0).hash256();
    }

    /// @notice                 calculates the signature hash of a Bitcoin transaction with the provided details
    /// @dev                    documented in bip143. many values are hardcoded here
    /// @param _outpoint        the bitcoin UTXO id (32-byte txid + 4-byte output index)
    /// @param _inputPKH        the input pubkeyhash (hash160(sender_pubkey))
    /// @param _inputValue      the value of the input in satoshi
    /// @param _outputValue     the value of the output in satoshi
    /// @param _outputPKH       the output pubkeyhash (hash160(recipient_pubkey))
    /// @return                 the double-sha256 (hash256) signature hash as defined by bip143
    function wpkhToWpkhSighash(
        bytes memory _outpoint,  // 36-byte UTXO id
        bytes20 _inputPKH,  // 20-byte hash160
        bytes8 _inputValue,  // 8-byte LE
        bytes8 _outputValue,  // 8-byte LE
        bytes20 _outputPKH  // 20-byte hash160
    ) internal view returns (bytes32) {
        return wpkhSpendSighash(
            _outpoint,
            _inputPKH,
            _inputValue,
            _outputValue,
            abi.encodePacked(
              hex"160014",  // wpkh tag
              _outputPKH)
            );
    }

    /// @notice                 Preserved for API compatibility with older version
    /// @dev                    documented in bip143. many values are hardcoded here
    /// @param _outpoint        the bitcoin UTXO id (32-byte txid + 4-byte output index)
    /// @param _inputPKH        the input pubkeyhash (hash160(sender_pubkey))
    /// @param _inputValue      the value of the input in satoshi
    /// @param _outputValue     the value of the output in satoshi
    /// @param _outputPKH       the output pubkeyhash (hash160(recipient_pubkey))
    /// @return                 the double-sha256 (hash256) signature hash as defined by bip143
    function oneInputOneOutputSighash(
        bytes memory _outpoint,  // 36-byte UTXO id
        bytes20 _inputPKH,  // 20-byte hash160
        bytes8 _inputValue,  // 8-byte LE
        bytes8 _outputValue,  // 8-byte LE
        bytes20 _outputPKH  // 20-byte hash160
    ) internal view returns (bytes32) {
        return wpkhToWpkhSighash(_outpoint, _inputPKH, _inputValue, _outputValue, _outputPKH);
    }

}