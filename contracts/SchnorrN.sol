// SPDX-License-Identifier: agpl-3.0
pragma solidity ^0.8.9;

contract SchnorrAccountAbstraction {
	uint256 constant internal Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

	bytes4 constant internal ERC1271_MAGICVALUE_BYTES32 = 0x1626ba7e;

	mapping (address => bytes32) public canSign;

	// add the combined multisig key on deploy
	constructor(address[] memory addrs) {
		uint len = addrs.length;
		for (uint i=0; i<len; i++) {
			canSign[addrs[i]] = bytes32(uint(1));
		}
	}

	function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
		if (canSign[_verifySchnorr(hash, signature)] != bytes32(0)) {
			return ERC1271_MAGICVALUE_BYTES32;
		} else {
			return 0xffffffff;
		}
	}

	function _verifySchnorr(bytes32 hash, bytes memory sig) internal pure returns (address) {
		// px := public key x-coord
		// e := schnorr signature challenge
		// s := schnorr signature
		// parity := public key y-coord parity (27 or 28)
		(bytes32 px, bytes32 e, bytes32 s, uint8 parity) = abi.decode(sig, (bytes32, bytes32, bytes32, uint8));
		// ecrecover = (m, v, r, s);
		bytes32 sp = bytes32(Q - mulmod(uint256(s), uint256(px), Q));
		bytes32 ep = bytes32(Q - mulmod(uint256(e), uint256(px), Q));

		require(uint256(sp) != Q);
		// the ecrecover precompile implementation checks that the `r` and `s`
		// inputs are non-zero (in this case, `px` and `ep`), thus we don't need to
		// check if they're zero.
		// ecrecover(hash, v, r, s);
		address R = ecrecover(sp, parity, px, ep);
		require(R != address(0), "ecrecover failed");
		return e == keccak256(abi.encodePacked(R, uint8(parity), px, hash))
			? address(uint160(uint256(px)))
			: address(0);
	}
}