import { createDecipheriv, createHash } from "crypto";
import {
  BadPaddingException,
  BadHashCheckException,
  ValueError,
} from "./errors.js";
/**
 * OID for JavaSoft proprietary key-protection algorithm.
 * @type {number[]}
 */
export const SUN_JKS_ALGO_ID = [1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1];

/**
 * OID for PBE_WITH_MD5_AND_DES3_CBC_OID (non-published, modified version of PKCS#5 PBEWithMD5AndDES).
 * @type {number[]}
 */
export const SUN_JCE_ALGO_ID = [1, 3, 6, 1, 4, 1, 42, 2, 19, 1];

/**
 * Encodes a string into UTF-16BE format.
 *
 * @param {string} str - The string to encode.
 * @returns {Buffer} A buffer representing the string in UTF-16BE encoding.
 */
export function encodeUtf16be(str) {
  const buffer = Buffer.from(str, "utf16le");
  return buffer.swap16();
}

/**
 * Generates an infinite keystream for XOR encryption/decryption using a given IV and password.
 *
 * @param {Buffer} iv - The initialization vector.
 * @param {Buffer} password - The UTF-16BE encoded password.
 * @yields {number} Bytes of the keystream.
 */
function* jksKeystream(iv, password) {
  let cur = iv;
  while (true) {
    const hash = createHash("sha1")
      .update(Buffer.concat([password, cur]))
      .digest();
    cur = Buffer.from(hash); // Ensure compatibility with Buffer operations
    for (const byte of cur) {
      yield byte;
    }
  }
}

/**
 * Encrypts a private key using the JKS keystore's password protection algorithm.
 *
 * @param {Buffer} key - The private key to be encrypted.
 * @param {string} passwordStr - The password used for encryption.
 * @returns {Buffer} The encrypted private key with IV and checksum appended.
 */
export function jksPkeyEncrypt(key, passwordStr) {
  const passwordBytes = encodeUtf16be(passwordStr); // Java chars are UTF-16BE code units
  const iv = crypto.randomBytes(20);

  const keyBuffer = Buffer.from(key);
  const keyStream = jksKeystream(iv, passwordBytes);
  const encryptedData = Buffer.alloc(keyBuffer.length);

  for (let i = 0; i < keyBuffer.length; i++) {
    encryptedData[i] = keyBuffer[i] ^ keyStream.next().value;
  }

  const check = createHash("sha1")
    .update(Buffer.concat([passwordBytes, keyBuffer]))
    .digest();
  return Buffer.concat([iv, encryptedData, check]);
}

/**
 * Decrypts a private key using the JKS keystore's password protection algorithm.
 *
 * @param {Buffer} data - The encrypted private key data.
 * @param {string} passwordStr - The password used for decryption.
 * @throws {BadHashCheckException} If the hash check fails (indicating a wrong password).
 * @returns {Buffer} The decrypted private key.
 */
export function jksPkeyDecrypt(data, passwordStr) {
  const passwordBytes = encodeUtf16be(passwordStr); // Java chars are UTF-16BE code units

  const dataBuffer = Buffer.from(data);
  const iv = dataBuffer.subarray(0, 20);
  const encryptedData = dataBuffer.subarray(20, -20);
  const check = dataBuffer.subarray(-20);

  const keyStream = jksKeystream(iv, passwordBytes);
  const decryptedKey = Buffer.alloc(encryptedData.length);

  for (let i = 0; i < encryptedData.length; i++) {
    decryptedKey[i] = encryptedData[i] ^ keyStream.next().value;
  }

  const recalculatedCheck = createHash("sha1")
    .update(Buffer.concat([passwordBytes, decryptedKey]))
    .digest();

  if (!recalculatedCheck.equals(check)) {
    throw new BadHashCheckException(
      "Bad hash check on private key; wrong password?"
    );
  }

  return Buffer.from(decryptedKey);
}

/**
 * Decrypts data using Sun's PBEWithMD5AndTripleDES password-based encryption scheme.
 *
 * @param {Buffer} data - The encrypted data.
 * @param {string} password - The ASCII password used for decryption.
 * @param {Buffer} salt - The 8-byte salt used for key and IV derivation.
 * @param {number} iterationCount - The number of hash iterations.
 * @returns {Buffer} The decrypted and unpadded data.
 */
export function jcePbeDecrypt(data, password, salt, iterationCount) {
  const { key, iv } = deriveKeyAndIv(password, salt, iterationCount);

  const decipher = createDecipheriv("des-ede3-cbc", key, iv);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);

  return stripPkcs5Padding(decrypted);
}

/**
 * Derives a Triple DES key and initialization vector (IV) from a password and salt.
 *
 * @param {string} password - The ASCII password.
 * @param {Buffer} salt - The 8-byte salt used for derivation.
 * @param {number} iterationCount - The number of hash iterations.
 * @throws {ValueError} If the salt is not 8 bytes.
 * @returns {{key: Buffer, iv: Buffer}} The derived key and IV.
 */
function deriveKeyAndIv(password, salt, iterationCount) {
  if (salt.length !== 8) {
    throw new ValueError(`Expected 8-byte salt, found ${salt.length} bytes`);
  }

  // Split salt into halves
  const saltHalves = [salt.subarray(0, 4), salt.subarray(4)];
  if (saltHalves[0].equals(saltHalves[1])) {
    saltHalves[0] = invertSaltHalf(saltHalves[0]);
  }

  const derived = Buffer.concat(
    saltHalves.map((saltHalf) => {
      let toBeHashed = saltHalf;
      for (let i = 0; i < iterationCount; i++) {
        toBeHashed = createHash("md5")
          .update(Buffer.concat([toBeHashed, Buffer.from(password, "ascii")]))
          .digest();
      }
      return toBeHashed;
    })
  );

  const key = derived.subarray(0, -8); // 24 bytes for Triple DES key
  const iv = derived.subarray(-8); // 8 bytes for initialization vector
  return { key, iv };
}

/**
 * Inverts the first half of the salt according to a specific (buggy) algorithm in JCE.
 *
 * @param {Buffer} saltHalf - The first 4 bytes of the salt.
 * @returns {Buffer} The "inverted" salt half.
 */
// function invertSaltHalf(saltHalf) {
//     const salt = Buffer.from(saltHalf);
//     const temp = salt[1];
//     salt[1] = salt[0];
//     salt[0] = salt[3];
//     salt[3] = salt[2];
//     salt[2] = temp;
//     return salt;
// }

/**
 * Inverts the first half of the salt according to a specific (buggy) algorithm in JCE.
 *
 * @param {Buffer} saltHalf - The first 4 bytes of the salt.
 * @returns {Buffer} The "inverted" salt half.
 */
function invertSaltHalf(saltHalf) {
  const salt = Buffer.from(saltHalf); // Convert to Buffer for byte manipulation
  salt[2] = salt[1];
  salt[1] = salt[0];
  salt[0] = salt[3];
  return salt;
}
