// SPDX-License-Identifier: MIT

pragma solidity ^0.8.16;

import "./libraries/VRF.sol";

contract VerifyVRF {

    function decodeProof(bytes memory _proof) public pure returns (uint[4] memory) {
        return VRF.decodeProof(_proof);
    }

    function verify(
        uint256[2] memory _publicKey,
        uint256[4] memory _proof,
        bytes memory _message
    ) public pure returns (bool) {
        return VRF.verify(_publicKey, _proof, _message);
    }
}