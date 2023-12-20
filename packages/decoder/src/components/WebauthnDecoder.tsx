import * as Asn1Ecc from "@peculiar/asn1-ecc";
import * as Asn1Schema from "@peculiar/asn1-schema";
import * as Ethers from "ethers";
import * as React from "react";
import * as WebauthnHelpers from "@simplewebauthn/server/helpers";

const EthersAbi = Ethers.AbiCoder.defaultAbiCoder();

export enum InputId {
  attestationData = "attestationData",
  credentialIdBase64Url = "credentialIdBase64Url",
  challengeHex = "challengeHex",
  authenticatorDataBase64Url = "authenticatorDataBase64Url",
  clientDataJsonBase64Url = "clientDataJsonBase64Url",
  signatureBase64Url = "signatureBase64Url",
}

export const WebauthnDecoder = () => {
  // Create Webauthn arguments
  const [credentialIdBase64Url, setCredentialIdBase64Url] =
    React.useState<string>("");
  const [credentialIdKeccak256, setCredentialIdKeccak256] =
    React.useState<string>("");
  const [attestationDataBase64Url, setAttestationDataBase64Url] =
    React.useState<string>("");
  const [publicKeyXUint256, setPublicKeyXUint256] = React.useState<bigint>(
    BigInt(0)
  );
  const [publicKeyYUint256, setPublicKeyYUint256] = React.useState<bigint>(
    BigInt(0)
  );

  // Get Webauthn arguments
  const [challengeHex, setChallengeHex] = React.useState<string>("");
  const [challengeBase64Url, setChallengeBase64Url] =
    React.useState<string>("");
  const [authenticatorDataBase64Url, setAuthenticatorDataBase64Url] =
    React.useState<string>("");
  const [authenticatorDataHex, setAuthenticatorDataHex] =
    React.useState<string>("");
  const [clientDataJsonBase64Url, setClientDataJsonBase64Url] =
    React.useState<string>("");
  const [clientDataJsonUtf8, setClientDataJsonUtf8] =
    React.useState<string>("");
  const [signatureBase64Url, setSignatureBase64Url] =
    React.useState<string>("");
  const [rUint256, setRUint256] = React.useState<bigint>(BigInt(0));
  const [sUint256, setSUint256] = React.useState<bigint>(BigInt(0));

  const inputChange = React.useCallback(
    async (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
      const { id, value } = event.target;
      switch (id) {
        // Create Webauthn arguments
        case InputId.credentialIdBase64Url:
          setCredentialIdBase64Url(value.toString());
          setCredentialIdKeccak256(
            parseCredentialIdBase64Url(value.toString())
          );
          break;
        case InputId.attestationData:
          setAttestationDataBase64Url(value.toString());
          const [credId, credPubKeyXUint256, credPubKeyYUint256] =
            parseAttestationDataBase64Url(value.toString());
          setCredentialIdBase64Url(credId);
          setCredentialIdKeccak256(parseCredentialIdBase64Url(credId));
          setPublicKeyXUint256(credPubKeyXUint256);
          setPublicKeyYUint256(credPubKeyYUint256);
          break;
        // Get Webauthn arguments
        case InputId.challengeHex:
          setChallengeHex(value.toString());
          setChallengeBase64Url(parseChallengeHex(value.toString()));
          break;
        case InputId.authenticatorDataBase64Url:
          setAuthenticatorDataBase64Url(value.toString());
          setAuthenticatorDataHex(
            parseAuthenticatorDataBase64Url(value.toString())
          );
          break;
        case InputId.clientDataJsonBase64Url:
          setClientDataJsonBase64Url(value.toString());
          setClientDataJsonUtf8(parseClientDataJsonBase64Url(value.toString()));
          break;
        case InputId.signatureBase64Url:
          setSignatureBase64Url(value.toString());
          const [rUint256, sUint256] = parseSignatureBase64Url(
            value.toString()
          );
          setRUint256(rUint256);
          setSUint256(sUint256);
          break;
        default:
          break;
      }
      console.log(`Input: ${id} = ${value}`);

      // ...
    },
    []
  );
  return (
    <>
      <div className="w-5/6 m-auto p-3 border-2 border-yellow-500 rounded-lg">
        <h1 className="text-3xl font-bold underline">Webauthn Decoder</h1>
        <h2 className="text-2xl font-bold">Create Webauthn</h2>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            credentialIdBase64Url
          </span>
          <input
            type="text"
            id={`${InputId.credentialIdBase64Url}`}
            value={`${credentialIdBase64Url}`}
            onChange={inputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            credentialIdKeccak256
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${credentialIdKeccak256}`}
          </span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            attestationDataBase64Url
          </span>
          <input
            type="text"
            id={`${InputId.attestationData}`}
            value={`${attestationDataBase64Url}`}
            onChange={inputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            credentialIdBase64Url
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${credentialIdBase64Url}`}
          </span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            publicKeyXUint256
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${publicKeyXUint256}`}
          </span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            publicKeyYUint256
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${publicKeyYUint256}`}
          </span>
        </div>
        <h2 className="text-2xl font-bold">Get Webauthn</h2>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            challengeHex
          </span>
          <input
            type="text"
            id={`${InputId.challengeHex}`}
            value={`${challengeHex}`}
            onChange={inputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            challengeBase64Url
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${challengeBase64Url}`}
          </span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            authenticatorDataBase64Url
          </span>
          <input
            type="text"
            id={`${InputId.authenticatorDataBase64Url}`}
            value={`${authenticatorDataBase64Url}`}
            onChange={inputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            authenticatorDataHex
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${authenticatorDataHex}`}
          </span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            clientDataJsonBase64Url
          </span>
          <input
            type="text"
            id={`${InputId.clientDataJsonBase64Url}`}
            value={`${clientDataJsonBase64Url}`}
            onChange={inputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            clientDataJsonUtf8
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${clientDataJsonUtf8}`}
          </span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            signatureBase64Url
          </span>
          <input
            type="text"
            id={`${InputId.signatureBase64Url}`}
            value={`${signatureBase64Url}`}
            onChange={inputChange}
            className="order-2 w-4/6 m-auto p-3 border-0 rounded-lg text-base"
          ></input>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            rUint256
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${rUint256}`}
          </span>
        </div>
        <div className="flex flex-row justify-center content-center flex-nowrap w-full h-auto">
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base">
            sUint256
          </span>
          <span className="order-1 w-2/6 m-auto p-3 border-0 rounded-lg text-base break-words">
            {`${sUint256}`}
          </span>
        </div>
      </div>
    </>
  );
};

const parseCredentialIdBase64Url = (credIdBase64Url: string): string => {
  if (!WebauthnHelpers.isoBase64URL.isBase64url(credIdBase64Url)) {
    console.log(`${credIdBase64Url} is not Base64Url`);
    return "" as const;
  }

  const credIdKeccak256 = Ethers.keccak256(
    Ethers.solidityPacked(["string"], [credIdBase64Url])
  );
  return credIdKeccak256;
};

const parseAttestationDataBase64Url = (
  attestObjBase64Url: string
): [string, bigint, bigint] => {
  if (!WebauthnHelpers.isoBase64URL.isBase64url(attestObjBase64Url)) {
    console.log(`${attestObjBase64Url} is not Base64Url`);
    return ["", BigInt(0), BigInt(0)] as const;
  }

  const attestObjUint8Arr =
    WebauthnHelpers.isoBase64URL.toBuffer(attestObjBase64Url);
  const decodedAttObj =
    WebauthnHelpers.decodeAttestationObject(attestObjUint8Arr);
  const authData = WebauthnHelpers.parseAuthenticatorData(
    decodedAttObj.get("authData")
  );
  const credIdUint8Arr = authData.credentialID
    ? authData.credentialID
    : Uint8Array.from([]);
  const credIdBase64Url =
    WebauthnHelpers.isoBase64URL.fromBuffer(credIdUint8Arr);
  const credPubKeyUint8Arr = authData.credentialPublicKey!;
  const credPubKeyObjUint8Arr =
    WebauthnHelpers.convertCOSEtoPKCS(credPubKeyUint8Arr);
  const credPubKeyXLen = (credPubKeyObjUint8Arr.length - 1) / 2; // tag length = 1

  const credPubKeyXUint8Arr = credPubKeyObjUint8Arr.subarray(
    1,
    1 + credPubKeyXLen
  );
  const credPubKeyXHex = `0x${WebauthnHelpers.isoUint8Array.toHex(
    credPubKeyXUint8Arr
  )}`;
  const credPubKeyXUint256 = EthersAbi.decode(
    ["uint256"],
    EthersAbi.encode(["bytes32"], [credPubKeyXHex])
  )[0] as bigint;

  const credPubKeyYUint8Arr = credPubKeyObjUint8Arr.subarray(
    1 + credPubKeyXLen
  );
  const credPubKeyYHex = `0x${WebauthnHelpers.isoUint8Array.toHex(
    credPubKeyYUint8Arr
  )}`;
  const credPubKeyYUint256 = EthersAbi.decode(
    ["uint256"],
    EthersAbi.encode(["bytes32"], [credPubKeyYHex])
  )[0] as bigint;

  return [credIdBase64Url, credPubKeyXUint256, credPubKeyYUint256] as const;
};

const parseChallengeHex = (challengeHex: string): string => {
  if (!Ethers.isHexString(challengeHex)) {
    console.log(`${challengeHex} is not HexString`);
    return "" as const;
  }

  const challengeUint8Arr = WebauthnHelpers.isoUint8Array.fromHex(
    challengeHex.slice(2)
  );
  const challengeBase64Url =
    WebauthnHelpers.isoBase64URL.fromBuffer(challengeUint8Arr);
  return challengeBase64Url;
};

const parseAuthenticatorDataBase64Url = (
  authenticatorDataBase64: string
): string => {
  if (!WebauthnHelpers.isoBase64URL.isBase64url(authenticatorDataBase64)) {
    console.log(`${authenticatorDataBase64} is not Base64Url`);
    return "" as const;
  }

  const authenticatorDataBase64Arr = WebauthnHelpers.isoBase64URL.toBuffer(
    authenticatorDataBase64
  );
  const authenticatorDataHex = `0x${WebauthnHelpers.isoUint8Array.toHex(
    authenticatorDataBase64Arr
  )}`;
  return authenticatorDataHex;
};

const parseClientDataJsonBase64Url = (
  clientDataJsonBase64Url: string
): string => {
  if (!WebauthnHelpers.isoBase64URL.isBase64url(clientDataJsonBase64Url)) {
    console.log(`${clientDataJsonBase64Url} is not Base64Url`);
    return "" as const;
  }

  const clientDataJSONUtf8 = WebauthnHelpers.isoBase64URL.toString(
    clientDataJsonBase64Url
  );
  return clientDataJSONUtf8;
};

const parseSignatureBase64Url = (
  signatureBase64Url: string
): [bigint, bigint] => {
  if (!WebauthnHelpers.isoBase64URL.isBase64url(signatureBase64Url)) {
    console.log(`${signatureBase64Url} is not Base64Url`);
    return [BigInt(0), BigInt(0)] as const;
  }

  const n = BigInt(
    "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
  );

  const signatureUint8Arr =
    WebauthnHelpers.isoBase64URL.toBuffer(signatureBase64Url);
  const parsedSignature = Asn1Schema.AsnParser.parse(
    signatureUint8Arr,
    Asn1Ecc.ECDSASigValue
  );
  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }
  const signatureRHex = `0x${WebauthnHelpers.isoUint8Array.toHex(rBytes)}`;
  const signatureRUint256 = EthersAbi.decode(
    ["uint256"],
    EthersAbi.encode(["bytes32"], [signatureRHex])
  )[0] as bigint;

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }
  const signatureSHex = `0x${WebauthnHelpers.isoUint8Array.toHex(sBytes)}`;
  let signatureSUint256 = EthersAbi.decode(
    ["uint256"],
    EthersAbi.encode(["bytes32"], [signatureSHex])
  )[0] as bigint;

  // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
  if (signatureSUint256 > n / BigInt(2)) {
    console.warn(
      `// [Warning] Non-malleable signatures, replacing old s-value: ${signatureSUint256}`
    );
    signatureSUint256 = n - signatureSUint256;
  }

  return [signatureRUint256, signatureSUint256] as const;
};

function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}
