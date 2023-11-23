// Bitcoin transaction parsing library

// Copyright 2016 rain <https://keybase.io/rain>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// https://en.bitcoin.it/wiki/Protocol_documentation#tx
//
// Raw Bitcoin transaction structure:
//
// field     | size | type     | description
// version   | 4    | int32    | transaction version number
// n_tx_in   | 1-9  | uint64   | number of transaction inputs
// tx_in     | 41+  | tx_in[]  | list of transaction inputs
// n_tx_out  | 1-9  | uint64   | number of transaction outputs
// tx_out    | 9+   | tx_out[] | list of transaction outputs
// lock_time | 4    | uint32   | block number / timestamp at which tx locked
//
// Transaction input (tx_in) structure:
//
// field      | size | type     | description
// previous   | 36   | outpoint | Previous output transaction reference
// script_len | 1-9  | uint64   | Length of the signature script
// sig_script | ?    | bytes[]  | Script for confirming transaction authorization
// sequence   | 4    | uint32   | Sender transaction version
//
// OutPoint structure:
//
// field      | size | type     | description
// hash       | 32   | bytes32  | The hash of the referenced transaction
// index      | 4    | uint32   | The index of this output in the referenced transaction
//
// Transaction output (tx_out) structure:
//
// field         | size | type     | description
// value         | 8    | int64    | Transaction value (Satoshis)
// pk_script_len | 1-9  | uint64   | Length of the public key script
// pk_script     | ?    | bytes[]  | Public key as a Bitcoin script.
//
// Variable integers (var_int) can be encoded differently depending
// on the represented value, to save space. Variable integers always
// precede an array of a variable length data type (e.g. tx_in).
//
// Variable integer encodings as a function of represented value:
//
// value           | bytes  | format
// <0xFD (253)     | 1      | uint8
// <=0xFFFF (65535)| 3      | 0xFD followed by length as uint16
// <=0xFFFF FFFF   | 5      | 0xFE followed by length as uint32
// -               | 9      | 0xFF followed by length as uint64
//
// Public key scripts `pk_script` are set on the output and can
// take a number of forms. The regular transaction script is
// called 'pay-to-pubkey-hash' (P2PKH):
//
// OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
//
// OP_x are Bitcoin script opcodes. The bytes representation (including
// the 0x14 20-byte stack push) is:
//
// 0x76 0xA9 0x14 <pubKeyHash> 0x88 0xAC
//
// The <pubKeyHash> is the ripemd160 hash of the sha256 hash of
// the public key, preceded by a network version byte. (21 bytes total)
//
// Network version bytes: 0x00 (mainnet); 0x6f (testnet); 0x34 (namecoin)
//
// The Bitcoin address is derived from the pubKeyHash. The binary form is the
// pubKeyHash, plus a checksum at the end.  The checksum is the first 4 bytes
// of the (32 byte) double sha256 of the pubKeyHash. (25 bytes total)
// This is converted to base58 to form the publicly used Bitcoin address.
// Mainnet P2PKH transaction scripts are to addresses beginning with '1'.
//
// P2SH ('pay to script hash') scripts only supply a script hash. The spender
// must then provide the script that would allow them to redeem this output.
// This allows for arbitrarily complex scripts to be funded using only a
// hash of the script, and moves the onus on providing the script from
// the spender to the redeemer.
//
// The P2SH script format is simple:
//
// OP_HASH160 <scriptHash> OP_EQUAL
//
// 0xA9 0x14 <scriptHash> 0x87
//
// The <scriptHash> is the ripemd160 hash of the sha256 hash of the
// redeem script. The P2SH address is derived from the scriptHash.
// Addresses are the scriptHash with a version prefix of 5, encoded as
// Base58check. These addresses begin with a '3'.

pragma solidity ^0.8.9;

import "hardhat/console.sol";
import "./BytesLib.sol";
import "./SECP256K1.sol";

library BTC {

    // Convert a variable integer into something useful and return it and
    // the index to after it.
    function parseVarInt(bytes memory txBytes, uint pos) internal pure returns (uint, uint) {
        // the first byte tells us how big the integer is
        uint8 ibit = uint8(txBytes[pos]);
        pos += 1;  // skip ibit

        if (ibit < 0xfd) {
            return (ibit, pos);
        } else if (ibit == 0xfd) {
            return (getBytesLE(txBytes, pos, 16), pos + 2);
        } else if (ibit == 0xfe) {
            return (getBytesLE(txBytes, pos, 32), pos + 4);
        } else if (ibit == 0xff) {
            return (getBytesLE(txBytes, pos, 64), pos + 8);
        }
    }

    // convert little endian bytes to uint
    function getBytesLE(bytes memory data, uint pos, uint bits) internal pure returns (uint) {
        if (bits == 8) {
            return uint(uint8(data[pos]));
        } else if (bits == 16) {
            return uint(uint16(uint8(data[pos])))
                 + (uint(uint16(uint8(data[pos + 1])) * 2 ** 8));
        } else if (bits == 32) {
            return uint(uint32(uint8(data[pos])))
                 + (uint(uint32(uint8(data[pos + 1])) * 2 ** 8))
                 + (uint(uint32(uint8(data[pos + 2])) * 2 ** 16))
                 + (uint(uint32(uint8(data[pos + 3])) * 2 ** 24));
        } else if (bits == 64) {
            return uint(uint64(uint8((data[pos]))))
                 + (uint(uint64(uint8(data[pos + 1])) * 2 ** 8))
                 + (uint(uint64(uint8(data[pos + 2])) * 2 ** 16))
                 + (uint(uint64(uint8(data[pos + 3])) * 2 ** 24))
                 + (uint(uint64(uint8(data[pos + 4])) * 2 ** 32))
                 + (uint(uint64(uint8(data[pos + 5])) * 2 ** 40))
                 + (uint(uint64(uint8(data[pos + 6])) * 2 ** 48))
                 + (uint(uint64(uint8(data[pos + 7])) * 2 ** 56));
        } 
    }

    // scan the full transaction bytes and return the first two output
    // values (in satoshis) and addresses (in binary)
    function getFirstTwoOutputs(bytes memory txBytes)
             internal pure returns (uint, bytes32, uint, bytes32)
    {
        uint pos;
        uint[] memory input_script_lens = new uint[](2); // (n) is the size of the array
        uint[] memory output_script_lens = new uint[](2);
        uint[] memory script_starts = new uint[](2);
        uint[] memory output_values = new uint[](2);
        bytes32[] memory output_addresses = new bytes32[](2);

        pos = 4;  // skip version

        (input_script_lens, pos) = scanInputs(txBytes, pos, 0);

        (output_values, script_starts, output_script_lens, pos) = scanOutputs(txBytes, pos, 2);

        for (uint i = 0; i < 2; i++) {
            bytes32 pkhash;
            pkhash = parseOutputScript(txBytes, script_starts[i], output_script_lens[i]);
            output_addresses[i] = pkhash;
        }

        return (output_values[0], output_addresses[0], output_values[1], output_addresses[1]);
    }


    // scan the full transaction bytes and return the first three output
    // values (in satoshis) and addresses (in binary)
    function parseThreeOutputs(bytes memory txBytes, uint pos, uint[] memory input_script_lens, uint[] memory output_script_lens, uint[] memory script_starts, uint[] memory output_values)
             internal pure returns (uint, bytes32, bytes32, bytes32, uint, bytes32, uint, bytes32)
    {

        (input_script_lens, pos) = scanInputs(txBytes, pos, 0);

        (output_values, script_starts, output_script_lens, pos) = scanOutputs(txBytes, pos, 0);

        bytes32[] memory output_addresses = new bytes32[](5);

        for (uint i = 0; i < 3; i++) {
            if (i==0) {
                (output_addresses[i], output_addresses[i+1],output_addresses[i+2]) = parseOutputScriptHTLC(txBytes, script_starts[i], output_script_lens[i]);
            }
            else {
                output_addresses[i+2] = parseOutputScript(txBytes, script_starts[i], output_script_lens[i]);
            }
        }

        return (output_values[0], output_addresses[0], output_addresses[1], output_addresses[2], output_values[1], output_addresses[3], output_values[2], output_addresses[4]);

    }

    // Check whether `btcAddress` is in the transaction outputs *and*
    // whether *at least* `value` has been sent to it.
    function checkValueSent(bytes memory txBytes, bytes20 btcAddress, uint value)
             internal pure returns (bool)
    {
        uint pos = 4;  // skip version
        (, pos) = scanInputs(txBytes, pos, 0);  // find end of inputs

        // scan *all* the outputs and find where they are
        (uint[] memory output_values, uint[] memory script_starts, uint[] memory output_script_lens,) = scanOutputs(txBytes, pos, 0);

        // look at each output and check whether it at least value to btcAddress
        for (uint i = 0; i < output_values.length; i++) {
            bytes32 pkhash;
            pkhash = parseOutputScript(txBytes, script_starts[i], output_script_lens[i]);
            if (pkhash == btcAddress && output_values[i] >= value) {
                return true;
            }
        }
        return false;
    }

    // scan the inputs and find the script lengths.
    // return an array of script lengths and the end position
    // of the inputs.
    // takes a 'stop' argument which sets the maximum number of
    // outputs to scan through. stop=0 => scan all.
    function scanInputs(bytes memory txBytes, uint pos, uint stop)
             internal pure returns (uint[] memory, uint)
    {
        uint n_inputs;
        uint halt;
        uint script_len;

        (n_inputs, pos) = parseVarInt(txBytes, pos);

        if (stop == 0 || stop > n_inputs) {
            halt = n_inputs;
        } else {
            halt = stop;
        }

        uint[] memory script_lens = new uint[](halt);

        for (uint i = 0; i < halt; i++) {
            pos += 36;  // skip outpoint
            (script_len, pos) = parseVarInt(txBytes, pos);
            script_lens[i] = script_len;
            pos += script_len + 4;  // skip sig_script, seq
        }

        return (script_lens, pos);
    }

    // scan the outputs and find the values and script lengths.
    // return an array of values, an array of script lengths, and the
    // end position of the outputs.
    // takes a 'stop' argument which sets the maximum number of
    // outputs to scan through. stop=0 => scan all.
    function scanOutputs(bytes memory txBytes, uint pos, uint stop)
             internal pure returns (uint[] memory, uint[] memory, uint[] memory, uint)
    {
        uint n_outputs;
        uint halt;
        uint script_len;

        (n_outputs, pos) = parseVarInt(txBytes, pos);

        if (stop == 0 || stop > n_outputs) {
            halt = n_outputs;
        } else {
            halt = stop;
        }

        uint[] memory script_starts = new uint[](halt);
        uint[] memory script_lens = new uint[](halt);
        uint[] memory output_values = new uint[](halt);

        for (uint i = 0; i < halt; i++) {
            output_values[i] = getBytesLE(txBytes, pos, 64);
            pos += 8;

            (script_len, pos) = parseVarInt(txBytes, pos);
            script_starts[i] = pos;
            script_lens[i] = script_len;
            pos += script_len;
        }

        return (output_values, script_starts, script_lens, pos);
    }

    // Slice 20 contiguous bytes from bytes `data`, starting at `start`
    function sliceBytes20(bytes memory data, uint start) internal pure returns (bytes20) {
        uint160 slice = 0;
        for (uint160 i = 0; i < 20; i++) {
            slice += uint160(uint8(data[i + start])) << (8 * (19 - i));
        }
        return bytes20(slice);
    }

    // Slice 1 contiguous bytes from bytes `data`, starting at `start`
    function sliceBytes1(bytes memory data, uint start) internal pure returns (bytes1) {
        uint8 slice = 0;
        for (uint8 i = 0; i < 1; i++) {
            slice += uint8(data[i + start]) << (8 * (0 - i));
        }
        return bytes1(slice);
    }

    // Slice 32 contiguous bytes from bytes `data`, starting at `start`
    function sliceBytes32(bytes memory data, uint start) internal pure returns (bytes32) {
        uint256 slice = 0;
        for (uint256 i = 0; i < 32; i++) {
            slice += uint256(uint8(data[i + start])) << (8 * (31 - i));
        }
        return bytes32(slice);
    }

    // Slice 31 contiguous bytes from bytes `data`, starting at `start`
    function sliceBytes31(bytes memory data, uint start) internal pure returns (bytes memory) {
        uint256 slice = 0;
        for (uint256 i = 0; i < 31; i++) {
            slice += uint256(uint8(data[i + start])) << (8 * (30 - i));
        }
        return BytesLib.uint256ToBytes(slice);
    }

    // returns true if the bytes located in txBytes by pos and
    // script_len represent a P2PKH script
    function isP2PKH(bytes memory txBytes, uint pos, uint script_len) internal pure returns (bool) {
        return (script_len == 25)           // 20-byte pubkeyhash + 5 bytes of script
            && (txBytes[pos] == 0x76)       // OP_DUP
            && (txBytes[pos + 1] == 0xa9)   // OP_HASH160
            && (txBytes[pos + 2] == 0x14)   // bytes to push
            && (txBytes[pos + 23] == 0x88)  // OP_EQUALVERIFY
            && (txBytes[pos + 24] == 0xac); // OP_CHECKSIG
    }

    // returns true if the bytes located in txBytes by pos and
    // script_len represent a P2SH script
    function isP2SH(bytes memory txBytes, uint pos, uint script_len) internal pure returns (bool) {
        return (script_len == 23)           // 20-byte scripthash + 3 bytes of script
            && (txBytes[pos + 0] == 0xa9)   // OP_HASH160
            && (txBytes[pos + 1] == 0x14)   // bytes to push
            && (txBytes[pos + 22] == 0x87); // OP_EQUAL
    }

    // returns true if the bytes located in txBytes by pos and
    // script_len represent a OP_RETURN script
    function isOPRETURN(bytes memory txBytes, uint pos, uint script_len) internal pure returns (bool) {
        return (script_len == 34)           // 32-byte the hash of the revocation secret + 2 bytes of script
            && (txBytes[pos + 0] == 0x6a)   // OP_RETURN
            && (txBytes[pos + 1] == 0x20);  // bytes to push (32)
    }

    function isLightningHTLC(bytes memory txBytes, uint pos, uint script_len) internal pure returns (bool) {
        return (script_len == 114)          // 32-byte the hash of the revocation secret + 2 bytes of script
            && (txBytes[pos + 0] == 0x76)   // OP_DUP
            && (txBytes[pos + 1] == 0x21)   // bytes to push (33)
            && (txBytes[pos + 35] == 0xac)  // OP_CHECKSIG
            && (txBytes[pos + 36] == 0x63)  // OP_IF
            && (txBytes[pos + 37] == 0x75)  // OP_DROP
            && (txBytes[pos + 38] == 0xaa)  // OP_HASH256
            && (txBytes[pos + 39] == 0x20)  // bytes to push (32)
            && (txBytes[pos + 72] == 0x88)  // OP_EQUALVERIFY
            && (txBytes[pos + 73] == 0x67)  // OP_ELSE
            && (txBytes[pos + 74] == 0x21)  // bytes to push (33)
            && (txBytes[pos + 108] == 0xad)  // OP_CHECKSIGVERIFY
            && (txBytes[pos + 109] == 0x52)  // OP_2
            && (txBytes[pos + 110] == 0xb2)  // OP_CHECKSEQUENCEVERIFY
            && (txBytes[pos + 111] == 0x75)  // OP_DROP
            && (txBytes[pos + 112] == 0x68)  // OP_ENDIF
            && (txBytes[pos + 113] == 0x51); // OP_1
    }    
    
    // Get the pubkeyhash / scripthash from an output script. Assumes
    // pay-to-pubkey-hash (P2PKH) or pay-to-script-hash (P2SH) outputs.
    // Returns the pubkeyhash/ scripthash, or zero if unknown output.
    function parseOutputScript(bytes memory txBytes, uint pos, uint script_len)
             internal pure returns (bytes32)
    {
        if (isP2PKH(txBytes, pos, script_len)) {
            //console.log("Parsed P2PKH output");
            return (sliceBytes20(txBytes, pos + 3));
        } else if (isP2SH(txBytes, pos, script_len)) {
            //console.log("Parsed P2SH output");
            return (sliceBytes20(txBytes, pos + 2));
        } else if (isOPRETURN(txBytes, pos, script_len)) {
            //console.log("Parsed OP_RETURN output");
            return (sliceBytes32(txBytes, pos + 2));
        } else if (isLightningHTLC(txBytes, pos, script_len)) {
            //console.log("Parsed LightningHTLC output");
            return (sliceBytes32(txBytes, pos + 2));
        } else {
            return bytes32(0);
        }
    }

    function parseOutputScriptHTLC(bytes memory txBytes, uint pos, uint script_len)
             internal pure returns (bytes32, bytes32, bytes32)
    {
        if (isLightningHTLC(txBytes, pos, script_len)) {
            //console.log("Parsed LightningHTLC output");
            //note: Compressed public keys are 33 bytes, consisting of a prefix either 0x02 or 0x03, and a 256-bit integer called x
            return (sliceBytes32(txBytes, pos + 3), sliceBytes32(txBytes, pos + 40), sliceBytes32(txBytes, pos + 76));
        } else {
            return (bytes32(0), bytes32(0), bytes32(0));
        }
    }

    function recoverPersonalSignPublicKey(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (bytes memory) {
        string memory header = '\x19Ethereum Signed Message:\n32';
        bytes32 _message = keccak256(abi.encodePacked(header, message));
        (uint256 x, uint256 y) = SECP256K1.recover(uint256(_message), v - 27, uint256(r), uint256(s));
        return abi.encodePacked(x, y);
    }
}