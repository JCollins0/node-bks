//Transpiled by AI (with help) source from https://github.com/kurtbrose/pyjks/blob/master/jks/jks.py
import { X509Certificate } from "crypto";
import { readFile, writeFile } from "fs/promises";
import {
  BadKeystoreFormatException,
  DecryptionFailureException,
  UnexpectedAlgorithmException,
  NotYetDecryptedException,
  UnsupportedKeyFormatException,
  NotImplementedError,
} from "./errors.js";

export class AbstractKeystore {
  /**
   *
   * @param {string} store_type
   * @param {Object.<string,AbstractKeystoreEntry>} entries - object mapping alias to AbstractKeystoreEntry
   */
  constructor(store_type, entries) {
    this.store_type = store_type; // A string indicating the type of keystore that was loaded.
    this.entries = Object.assign({}, entries); // A dictionary of all entries in the keystore, mapped by alias.
  }

  static load(filename, store_password, try_decrypt_keys = true) {
    return new Promise(async (resolve, reject) => {
      try {
        const filebytes = await readFile(filename);
        const keystore = this.loads(
          filebytes,
          store_password,
          try_decrypt_keys
        );
        resolve(keystore);
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Load keystore from a byte string.
   * @param {Buffer} data
   * @param {string} store_password
   * @param {boolean} try_decrypt_keys
   */
  static loads(data, store_password, try_decrypt_keys = true) {
    throw new NotImplementedError("Abstract method");
  }

  save(filename, store_password) {
    return new Promise(async (resolve, reject) => {
      try {
        await writeFile(filename, this.saves(store_password));
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  }

  saves(store_password) {
    throw new NotImplementedError("Abstract method");
  }

  static _read_utf(data, pos, kind = null) {
    const size = Buffer.from(data, pos).readUInt16BE();
    pos += 2;
    try {
      return [data.slice(pos, pos + size).toString("utf-8"), pos + size];
    } catch (e) {
      if (kind) {
        throw new BadKeystoreFormatException(
          `Failed to read ${kind}, contains bad UTF-8 data: ${e}`
        );
      } else {
        throw new BadKeystoreFormatException(
          `Encountered bad UTF-8 data: ${e}`
        );
      }
    }
  }

  static _read_data(data, pos) {
    const size = Buffer.from(data, pos).readUInt32BE();
    pos += 4;
    return [data.slice(pos, pos + size), pos + size];
  }

  static _write_utf(text) {
    const encodedText = Buffer.from(text, "utf-8");
    const size = encodedText.length;
    let result = Buffer.alloc(2);
    result.writeUInt16BE(size, 0);
    result = Buffer.concat([result, encodedText]);
    return result;
  }

  static _write_data(data) {
    const size = data.length;
    let result = Buffer.alloc(4);
    result.writeUInt32BE(size, 0);
    result = Buffer.concat([result, data]);
    return result;
  }
}

export class AbstractKeystoreEntry {
  constructor({ store_type, alias, timestamp } = {}) {
    this.store_type = store_type;
    this.alias = alias;
    this.timestamp = timestamp;
  }

  static new(alias) {
    throw new NotImplementedError("Abstract method");
  }

  is_decrypted() {
    throw new NotImplementedError("Abstract method");
  }

  decrypt(key_password) {
    throw new NotImplementedError("Abstract method");
  }

  encrypt(key_password) {
    throw new NotImplementedError("Abstract method");
  }
}

export class TrustedCertEntry extends AbstractKeystoreEntry {
  constructor({ store_type, alias, timestamp, type, cert } = {}) {
    super({ store_type, alias, timestamp });
    this.type = type; // A string indicating the type of certificate.
    this.cert = cert; // A byte string containing the actual certificate data.
  }

  static new(alias, cert) {
    const timestamp = Date.now();
    const tke = new this({
      timestamp: timestamp,
      alias: alias.toLowerCase(),
      cert: cert,
    });
    return tke;
  }

  is_decrypted() {
    return true;
  }

  decrypt(key_password) {
    return;
  }

  encrypt(key_password) {
    return;
  }

  decodeX509Certificate() {
    try {
      const cert = new X509Certificate(this.cert);

      return {
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        serialNumber: cert.serialNumber,
        publicKey: cert.publicKey,
        x509cert: cert,
      };
    } catch (error) {
      console.error("Error decoding certificate:", error.message);
      return null;
    }
  }
}

export class PrivateKeyEntry extends AbstractKeystoreEntry {
  constructor({
    store_type,
    alias,
    timestamp,
    cert_chain,
    encrypted,
    pkey,
    pkey_pkcs8,
    algorithm_oid,
  } = {}) {
    super({ store_type, alias, timestamp });
    this.cert_chain = cert_chain || [];
    this._encrypted = encrypted;
    this._pkey = pkey;
    this._pkey_pkcs8 = pkey_pkcs8;
    this._algorithm_oid = algorithm_oid;
  }

  static new(alias, certs, key, key_format = "pkcs8") {
    const timestamp = Date.now();
    const cert_chain = certs.map((cert) => ["X.509", cert]);
    const pke = new this({
      timestamp: timestamp,
      alias: alias.toLowerCase(),
      cert_chain: cert_chain,
    });

    if (key_format === "pkcs8") {
      const privateKeyInfo = this._decodeKey(key);
      pke._algorithm_oid = privateKeyInfo.privateKeyAlgorithm.algorithm;
      pke._pkey = privateKeyInfo.privateKey;
      pke._pkey_pkcs8 = key;
    } else if (key_format === "rsa_raw") {
      pke._algorithm_oid = "RSA_ENCRYPTION_OID";
      pke._pkey_pkcs8 = this._encodePkcs8Key(key);
      pke._pkey = key;
    } else {
      throw new UnsupportedKeyFormatException(
        `Key Format '${key_format}' is not supported`
      );
    }

    return pke;
  }

  __getattr__(name) {
    if (!this.is_decrypted()) {
      throw new NotYetDecryptedException(
        `Cannot access attribute '${name}'; entry not yet decrypted, call decrypt() with the correct password first`
      );
    }
    return this[`_${name}`];
  }

  is_decrypted() {
    return !this._encrypted;
  }

  decrypt(key_password) {
    if (this.is_decrypted()) return;

    const encryptedInfo = this._decodeKey(this._encrypted); // #MISSING IMPL
    // const algo_id = encryptedInfo.encryptionAlgorithm.algorithm; // #MISSING IMPL
    // const algo_params = encryptedInfo.encryptionAlgorithm.parameters; // #MISSING IMPL
    // const encrypted_private_key = encryptedInfo.encryptedData; // #MISSING IMPL

    let plaintext = null;
    try {
      // #MISSING IMPL
      // if (algo_id === sun_crypto.SUN_JKS_ALGO_ID) {
      //     plaintext = sun_crypto.jks_pkey_decrypt(encrypted_private_key, key_password); // #MISSING IMPL
      // } else if (algo_id === sun_crypto.SUN_JCE_ALGO_ID) {
      //     if (this.store_type !== 'jceks') {
      //         throw new UnexpectedAlgorithmException('Encountered JCEKS private key protection algorithm in JKS keystore');
      //     }
      //     // #MISSING IMPL
      //     const salt = params['salt']; // #MISSING IMPL
      //     const iteration_count = params['iterationCount']; // #MISSING IMPL
      //     plaintext = sun_crypto.jce_pbe_decrypt(encrypted_private_key, key_password, salt, iteration_count); // #MISSING IMPL
      // } else {
      //     throw new UnexpectedAlgorithmException(`Unknown ${this.store_type.toUpperCase()} private key protection algorithm: ${algo_id}`);
      // }
    } catch (error) {
      throw new DecryptionFailureException(
        `Failed to decrypt data for private key '${this.alias}'; wrong password?`
      );
    }

    const privateKeyInfo = this._decodeKey(plaintext); // #MISSING IMPL
    this._encrypted = null;
    this._pkey = privateKeyInfo.privateKey;
    this._pkey_pkcs8 = plaintext;
    this._algorithm_oid = privateKeyInfo.privateKeyAlgorithm.algorithm;
  }

  encrypt(key_password) {
    if (!this.is_decrypted()) return;

    const encrypted_private_key = sun_crypto.jks_pkey_encrypt(
      this.pkey_pkcs8,
      key_password
    ); // #MISSING IMPL

    // #MISSING IMPL
    // const epki = new rfc5208.EncryptedPrivateKeyInfo();
    // epki.setComponentByName('encryptionAlgorithm', {
    //     algorithm: sun_crypto.SUN_JKS_ALGO_ID,
    //     parameters: '\x05\x00'
    // });
    // epki.setComponentByName('encryptedData', encrypted_private_key);

    this._encrypted = null; // #MISSING IMPL
    this._pkey = null;
    this._pkey_pkcs8 = null;
    this._algorithm_oid = null;
  }

  static _decodeKey(key) {
    // #MISSING IMPL
  }

  static _encodePkcs8Key(key) {
    // #MISSING IMPL
  }
}

export default {
  AbstractKeystore,
  AbstractKeystoreEntry,
  TrustedCertEntry,
  PrivateKeyEntry,
  BadKeystoreFormatException,
  DecryptionFailureException,
  UnexpectedAlgorithmException,
  NotYetDecryptedException,
  UnsupportedKeyFormatException,
};
