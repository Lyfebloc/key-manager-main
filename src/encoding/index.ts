import { sign } from "tweetnacl";
import base32 from "hi-base32";
import sha512 from "js-sha512";

export const naclPublicKeyLength = sign.publicKeyLength;
export const naclSecretKeyLength = sign.secretKeyLength;
export const naclHashBytesLength = 32;
export const naclSeedBytesLength = 32;

const ALGORAND_ADDRESS_BYTE_LENGTH = 36;
const ALGORAND_CHECKSUM_BYTE_LENGTH = 4;
const ALGORAND_ADDRESS_LENGTH = 58;
export const ALGORAND_ZERO_ADDRESS_STRING =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ";

export const MALFORMED_ADDRESS_ERROR_MSG = "address seems to be malformed";
export const CHECKSUM_ADDRESS_ERROR_MSG = "wrong checksum for address";
export const INVALID_MSIG_VERSION_ERROR_MSG = "invalid multisig version";
export const INVALID_MSIG_THRESHOLD_ERROR_MSG = "bad multisig threshold";
export const INVALID_MSIG_PK_ERROR_MSG =
  "bad multisig public key - wrong length";
export const UNEXPECTED_PK_LEN_ERROR_MSG =
  "nacl public key length is not 32 bytes";

/**
 * Takes an Algorand address as a Uint8Array and encodes it into a string with checksum.
 * @param address - a raw Algorand address
 * @returns the address and checksum encoded as a string.
 */
export function encodeAlgorandAdress(address: Uint8Array): string {
  // compute checksum
  const checksum = genericHash(address).slice(
    naclPublicKeyLength - ALGORAND_CHECKSUM_BYTE_LENGTH,
    naclPublicKeyLength
  );
  const addr = base32.encode(concatArrays(address, checksum));

  return addr.toString().slice(0, ALGORAND_ADDRESS_LENGTH); // removing the extra '===='
}

/**
 * Decoded Algorand address. Includes public key and checksum.
 */
export interface AlgorandAddress {
  publicKey: Uint8Array;
  checksum: Uint8Array;
}

/**
 * decodeAddress takes an Algorand address in string form and decodes it into a Uint8Array.
 * @param address - an Algorand address with checksum.
 * @returns the decoded form of the address's public key and checksum
 */
export function decodeAddress(address: string): AlgorandAddress {
  if (typeof address !== "string" || address.length !== ALGORAND_ADDRESS_LENGTH)
    throw new Error(MALFORMED_ADDRESS_ERROR_MSG);

  // try to decode
  const decoded = base32.decode.asBytes(address.toString());
  // Sanity check
  if (decoded.length !== ALGORAND_ADDRESS_BYTE_LENGTH)
    throw new Error(MALFORMED_ADDRESS_ERROR_MSG);

  // Find publickey and checksum
  const pk = new Uint8Array(
    decoded.slice(
      0,
      ALGORAND_ADDRESS_BYTE_LENGTH - ALGORAND_CHECKSUM_BYTE_LENGTH
    )
  );
  const cs = new Uint8Array(
    decoded.slice(naclPublicKeyLength, ALGORAND_ADDRESS_BYTE_LENGTH)
  );

  // Compute checksum
  const checksum = genericHash(pk).slice(
    naclHashBytesLength - ALGORAND_CHECKSUM_BYTE_LENGTH,
    naclHashBytesLength
  );

  // Check if the checksum and the address are equal
  if (!arrayEqual(checksum, cs)) throw new Error(CHECKSUM_ADDRESS_ERROR_MSG);

  return { publicKey: pk, checksum: cs };
}

/**
 * ConcatArrays takes n number arrays and returns a joint Uint8Array
 * @param arrs - An arbitrary number of n array-like number list arguments
 * @returns [a,b]
 */
function concatArrays(...arrs: ArrayLike<number>[]) {
  const size = arrs.reduce((sum, arr) => sum + arr.length, 0);
  const c = new Uint8Array(size);

  let offset = 0;
  for (let i = 0; i < arrs.length; i++) {
    c.set(arrs[i], offset);
    offset += arrs[i].length;
  }

  return c;
}

function genericHash(arr: sha512.Message) {
  return sha512.sha512_256.array(arr);
}

/**
 * ArrayEqual takes two arrays and return true if equal, false otherwise
 */
function arrayEqual(a: ArrayLike<any>, b: ArrayLike<any>) {
  if (a.length !== b.length) {
    return false;
  }
  return Array.from(a).every((val, i) => val === b[i]);
}
