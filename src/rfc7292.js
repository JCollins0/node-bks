//Reference: https://github.com/kurtbrose/pyjks/blob/master/jks/rfc7292.py
import { BadDataLengthException } from "./errors.js";
import { createHashAlgorithm } from "./hashes.js";

import crypto from "crypto";

export const PURPOSE_KEY_MATERIAL = 1;
export const PURPOSE_IV_MATERIAL = 2;
export const PURPOSE_MAC_MATERIAL = 3;

/**
 *
 * @param {string} hashfn
 * @param {number} purpose_byte
 * @param {string} password_str
 * @param {Buffer} salt
 * @param {number} iteration_count
 * @param {number} desired_key_size
 * @returns {Buffer}
 */
export function derive_key(
  hashfn,
  purpose_byte,
  password_str,
  salt,
  iteration_count,
  desired_key_size
) {
  // Implements PKCS#12 key derivation as specified in RFC 7292, Appendix B.
  const hashFN = () => createHashAlgorithm(hashfn);

  const password_bytes =
    password_str.length > 0
      ? Buffer.concat([
          Buffer.from(password_str, "utf16le").swap16(),
          Buffer.from([0x00, 0x00]),
        ])
      : Buffer.alloc(0);

  const u = hashFN().digest().length; // in bytes
  const v = hashFN().block_size(); // block_size in bytes

  const _salt = Buffer.from(salt);
  const _password_bytes = Buffer.from(password_bytes);

  const D = Buffer.alloc(v, purpose_byte);
  const S = Buffer.alloc(Math.ceil(_salt.length / v) * v, _salt);
  const P = Buffer.alloc(
    Math.ceil(_password_bytes.length / v) * v,
    _password_bytes
  );

  const I = Buffer.concat([S, P]);
  const c = Math.ceil(desired_key_size / u);
  let derived_key = Buffer.alloc(0);

  for (let i = 1; i <= c; i++) {
    let A = hashFN()
      .update(Buffer.concat([D, I]))
      .digest();
    for (let j = 0; j < iteration_count - 1; j++) {
      A = hashFN().update(A).digest();
    }

    const B = Buffer.alloc(v, A);

    for (let j = 0; j < I.length / v; j++) {
      adjust(I, j * v, B);
    }

    derived_key = Buffer.concat([derived_key, A]);
  }

  return derived_key.subarray(0, desired_key_size);
}

/**
 * Adjust bytes. To be honest I don't know what this function does.
 * @param {Buffer} a
 * @param {int} a_offset
 * @param {Buffer} b
 */
export function adjust(a, a_offset, b) {
  // a = Uint8Array
  // a_offset = int
  // b = Uint8Array

  let x = (b[b.length - 1] & 0xff) + (a[a_offset + b.length - 1] & 0xff) + 1;
  a[a_offset + b.length - 1] = x & 0xff;
  x >>= 8;

  for (let i = b.length - 2; i >= 0; i--) {
    x += (b[i] & 0xff) + (a[a_offset + i] & 0xff);
    a[a_offset + i] = x & 0xff;
    x >>= 8;
  }
}

export function decryptPBEWithSHAAnd3KeyTripleDESCBC(
  data,
  passwordStr,
  salt,
  iterationCount
) {
  // Derive IV and key
  const iv = derive_key(
    "sha1",
    PURPOSE_IV_MATERIAL,
    passwordStr,
    salt,
    iterationCount,
    64 / 8
  );
  const key = derive_key(
    "sha1",
    PURPOSE_KEY_MATERIAL,
    passwordStr,
    salt,
    iterationCount,
    192 / 8
  );

  // Validate data length
  if (data.length % 8 !== 0) {
    throw new BadDataLengthException(
      "Encrypted data length is not a multiple of 8 bytes"
    );
  }

  // Decrypt using Triple DES in CBC mode
  const decipher = crypto.createDecipheriv("des-ede3-cbc", key, iv);
  let decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted;
}
