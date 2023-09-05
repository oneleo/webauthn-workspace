// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "./interfaces/IPasskeyManager.sol";
import "./core/PasskeyVerificationLibrary.sol";
import "./utils/Base64.sol";

contract VerifyPasskey {
    mapping(bytes32 => Passkey) private PasskeysAuthorised;
    bytes32[] public KnownEncodedIdHashes;

    function base64(bytes32 input) public pure returns (string memory output) {
        return Base64.encode(bytes.concat(input));
    }

    function addPasskey(
        string calldata _encodedId,
        uint256 _publicKeyX,
        uint256 _publicKeyY
    ) public {
        bytes32 hashEncodedId = keccak256(abi.encodePacked(_encodedId));
        require(
            PasskeysAuthorised[hashEncodedId].pubKeyX == 0 &&
                PasskeysAuthorised[hashEncodedId].pubKeyY == 0,
            "PM01: Passkey already exists"
        );
        Passkey memory passkey = Passkey({
            pubKeyX: _publicKeyX,
            pubKeyY: _publicKeyY
        });
        KnownEncodedIdHashes.push(hashEncodedId);
        PasskeysAuthorised[hashEncodedId] = passkey;
    }

    function validateSignature(
        uint256 r,
        uint256 s,
        bytes memory authenticatorData,
        bytes memory clientDataJSONPack,
        bytes32 encodedIdHash,
        bytes32 userOpHash
    ) external view returns (uint256) {
        bytes32 message;
        {
            (
                string memory clientDataJSONPre,
                string memory clientDataJSONPost
            ) = abi.decode(clientDataJSONPack, (string, string));

            string memory opHashBase64 = Base64.encode(
                bytes.concat(userOpHash)
            );

            string memory clientDataJSON = string.concat(
                clientDataJSONPre,
                opHashBase64,
                clientDataJSONPost
            );

            bytes32 clientHash = sha256(bytes(clientDataJSON));

            message = sha256(bytes.concat(authenticatorData, clientHash));
        }

        Passkey memory passKey;
        {
            passKey = PasskeysAuthorised[encodedIdHash];
        }

        require(
            passKey.pubKeyX != 0 && passKey.pubKeyY != 0,
            "PM06: Passkey doesn't exist"
        );
        require(
            Secp256r1.Verify(passKey, r, s, uint(message)),
            "PM07: Invalid signature"
        );
        return 0;
    }

    function verifySignature(
        uint256 pubKeyX,
        uint256 pubKeyY,
        uint256 r,
        uint256 s,
        bytes memory authenticatorData,
        bytes memory clientDataJSONPack,
        bytes32 userOpHash
    ) external view returns (uint256) {
        bytes32 message;
        {
            (
                string memory clientDataJSONPre,
                string memory clientDataJSONPost
            ) = abi.decode(clientDataJSONPack, (string, string));

            string memory opHashBase64 = Base64.encode(
                bytes.concat(userOpHash)
            );

            string memory clientDataJSON = string.concat(
                clientDataJSONPre,
                opHashBase64,
                clientDataJSONPost
            );

            bytes32 clientHash = sha256(bytes(clientDataJSON));

            message = sha256(bytes.concat(authenticatorData, clientHash));
        }

        Passkey memory passKey;
        {
            passKey = Passkey(pubKeyX, pubKeyY);
        }

        require(
            passKey.pubKeyX != 0 && passKey.pubKeyY != 0,
            "PM06: Passkey doesn't exist"
        );
        require(
            Secp256r1.Verify(passKey, r, s, uint(message)),
            "PM07: Invalid signature"
        );
        return 0;
    }
}
