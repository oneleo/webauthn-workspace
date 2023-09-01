// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "./interfaces/IPasskeyManager.sol";
import "./core/PasskeyVerificationLibrary.sol";
import "./utils/Base64.sol";

contract VerifyPasskey {
    function base64(
        bytes32 input
    ) external pure returns (string memory output) {
        return Base64.encode(bytes.concat(input));
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
