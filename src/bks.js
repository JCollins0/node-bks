// https://pyjks.readthedocs.io/en/latest/_modules/jks/bks.html
import {
  AbstractKeystore,
  AbstractKeystoreEntry,
  TrustedCertEntry,
} from "./classes.js";
import {
  DecryptionFailureException,
  NotYetDecryptedException,
  UnexpectedKeyEncodingException,
  UnsupportedKeystoreVersionException,
  BadKeystoreFormatException,
  KeystoreSignatureException,
  DuplicateAliasException,
} from "./errors.js";
import {
  decryptPBEWithSHAAnd3KeyTripleDESCBC,
  derive_key,
  PURPOSE_MAC_MATERIAL,
} from "./rfc7292.js";
import forge from "node-forge";
import {
  pbkdf2Sync,
  createDecipheriv,
  createHmac,
  timingSafeEqual,
  createHash,
} from "crypto";

const ENTRY_TYPE_CERTIFICATE = 1;
const ENTRY_TYPE_KEY = 2; // plaintext key entry
const ENTRY_TYPE_SECRET = 3; // arbitrary data
const ENTRY_TYPE_SEALED = 4; // protected keys

const KEY_TYPE_PRIVATE = 0;
const KEY_TYPE_PUBLIC = 1;
const KEY_TYPE_SECRET = 2;

export class AbstractBksEntry extends AbstractKeystoreEntry {
  /**
   *
   * @param {object} kwargs
   * @param {string} kwargs.alias
   * @param {number} kwargs.timestamp
   * @param {string} kwargs.store_type
   * @param {Array<*>} kwargs.cert_chain
   * @param {Buffer} kwargs.encrypted
   */
  constructor(kwargs) {
    super(kwargs);
    this.cert_chain = kwargs.cert_chain || [];
    this._encrypted = kwargs.encrypted;
  }
}

export class BksTrustedCertEntry extends TrustedCertEntry {
  // Identical to AbstractBksEntry, no additional implementation needed
}

export class BksKeyEntry extends AbstractBksEntry {
  constructor(type, format, algorithm, encoded, kwargs) {
    super(kwargs);
    this.type = type;
    this.format = format;
    this.algorithm = algorithm;
    this.encoded = encoded;

    if (this.type === KEY_TYPE_PRIVATE) {
      if (!["PKCS8", "PKCS#8"].includes(this.format)) {
        throw new UnexpectedKeyEncodingException(
          `Unexpected encoding for private key entry: '${this.format}'`
        );
      }

      const privateKeyInfoAsn1 = forge.asn1.fromDer(
        forge.util.createBuffer(this.encoded)
      );

      // TODO MAYBE Instead of hardcoding the indecies i can filter based on type?
      const algorithm = privateKeyInfoAsn1.value[1].value[0].value;
      this.pkey_pkcs8 = this.encoded;
      const privateKeyData = forge.pki.privateKeyFromAsn1(privateKeyInfoAsn1);
      this.pkey = forge.pki.privateKeyToPem(privateKeyData);
      this.algorithm_oid = forge.asn1.derToOid(algorithm);
    } else if (this.type === KEY_TYPE_PUBLIC) {
      if (!["X.509", "X509"].includes(this.format)) {
        throw new UnexpectedKeyEncodingException(
          `Unexpected encoding for public key entry: '${this.format}'`
        );
      }
      const spki = forge.asn1.fromDer(forge.util.createBuffer(this.encoded)); // ASN.1 decoding required
      const algorithm = spki.value[0].value[0].value;
      const pubkey = forge.pki.publicKeyFromAsn1(spki);
      this.public_key_info = this.encoded;
      this.public_key = forge.pki.publicKeyToPem(pubkey);
      this.algorithm_oid = forge.asn1.derToOid(algorithm);
    } else if (this.type === KEY_TYPE_SECRET) {
      if (this.format !== "RAW") {
        throw new UnexpectedKeyEncodingException(
          `Unexpected encoding for raw key entry: '${this.format}'`
        );
      }
      this.key = encoded;
      this.key_size = encoded.length * 8;
    } else {
      throw new UnexpectedKeyEncodingException(
        `Key format '${this.format}' not recognized`
      );
    }
  }

  is_decrypted() {
    return true;
  }

  decrypt(key_password) {
    // Does nothing for this entry type
  }

  static type2str(t) {
    if (t === KEY_TYPE_PRIVATE) return "PRIVATE";
    if (t === KEY_TYPE_PUBLIC) return "PUBLIC";
    if (t === KEY_TYPE_SECRET) return "SECRET";
    return null;
  }
}

export class BksSecretKeyEntry extends AbstractBksEntry {
  constructor(kwargs) {
    super(kwargs);
    this.key = this._encrypted;
  }

  is_decrypted() {
    return true;
  }

  decrypt(key_password) {
    // Does nothing for this entry type
  }
}

export class BksSealedKeyEntry extends AbstractBksEntry {
  constructor(kwargs) {
    super(kwargs);
    this._nested = null; // nested BksKeyEntry once decrypted
  }

  __getattr__(name) {
    if (!this.is_decrypted()) {
      throw new NotYetDecryptedException(
        `Cannot access attribute '${name}'; entry not yet decrypted, call decrypt() with the correct password first`
      );
    }
    if (this[`_${name}`]) {
      return this[`_${name}`];
    } else {
      return this._nested[name];
    }
  }

  is_decrypted() {
    return !this._encrypted;
  }

  decrypt(key_password) {
    if (this.is_decrypted()) return;
    let pos = 0;
    const data = this._encrypted;

    const [salt, newPos] = BksKeyStore._read_data(data, pos);
    pos = newPos;
    const iteration_count = data.readUInt32BE(pos);
    pos += 4;
    const encrypted_blob = data.subarray(pos);

    try {
      const decrypted = decryptPBEWithSHAAnd3KeyTripleDESCBC(
        encrypted_blob,
        key_password,
        salt,
        iteration_count
      );
      const key_entry = BksKeyStore._read_bks_key(
        decrypted,
        0,
        this.store_type
      );
      key_entry.store_type = this.store_type;
      key_entry.cert_chain = this.cert_chain;
      key_entry.alias = this.alias;
      key_entry.timestamp = this.timestamp;

      this._nested = key_entry;
      this._encrypted = null;
    } catch (error) {
      throw new DecryptionFailureException(
        `Failed to decrypt data for key '${this.alias}'; wrong password?`
      );
    }
  }
}

export class BksKeyStore extends AbstractKeystore {
  /**
   *
   * @param {string} store_type
   * @param {AbstractBksEntry[]} entries
   * @param {number} version
   */
  constructor(store_type, entries, version = 2) {
    super(store_type, entries);
    this.version = version;
  }

  get certs() {
    return Object.fromEntries(
      Object.entries(this.entries).filter(
        ([_, entry]) => entry instanceof BksTrustedCertEntry
      )
    );
  }

  get secret_keys() {
    return Object.fromEntries(
      Object.entries(this.entries).filter(
        ([_, entry]) => entry instanceof BksSecretKeyEntry
      )
    );
  }

  get sealed_keys() {
    return Object.fromEntries(
      Object.entries(this.entries).filter(
        ([_, entry]) => entry instanceof BksSealedKeyEntry
      )
    );
  }

  get plain_keys() {
    return Object.fromEntries(
      Object.entries(this.entries).filter(
        ([_, entry]) => entry instanceof BksKeyEntry
      )
    );
  }

  /**
   *
   * @param {Buffer} data
   * @param {string} store_password
   * @param {boolean} try_decrypt_keys
   * @returns
   */
  static loads(data, store_password, try_decrypt_keys = true) {
    try {
      let pos = 0;
      const version = data.readUInt32BE(pos);
      pos += 4;
      if (![1, 2].includes(version)) {
        throw new UnsupportedKeystoreVersionException(
          `Unsupported BKS keystore version; only V1 and V2 supported, found v${version}`
        );
      }

      const [salt, newPos1] = BksKeyStore._read_data(data, pos);
      pos = newPos1;
      const iteration_count = data.readUInt32BE(pos);
      pos += 4;

      const store_type = "bks";
      const [entries, size] = BksKeyStore._load_bks_entries(
        data.subarray(pos),
        store_type,
        store_password,
        try_decrypt_keys
      );

      const hmac_fn = "sha1";
      const hmac_digest_size = createHmac(hmac_fn, "").digest().length;
      const hmac_key_size =
        version !== 1 ? hmac_digest_size * 8 : hmac_digest_size;
      const hmac_key = derive_key(
        hmac_fn,
        PURPOSE_MAC_MATERIAL, // HMAC key purpose byte
        store_password,
        salt,
        iteration_count,
        hmac_key_size / 8
      );

      pos += size;
      const store_data = data.subarray(pos - size, pos);
      const store_hmac = data.subarray(pos, pos + hmac_digest_size);

      if (store_hmac.length !== hmac_digest_size) {
        throw new BadKeystoreFormatException(
          `Bad HMAC size; found ${store_hmac.length} bytes, expected ${hmac_digest_size}`
        );
      }

      const hmac = createHmac(hmac_fn, hmac_key);
      hmac.update(store_data);
      const computed_hmac = hmac.digest();

      if (!timingSafeEqual(store_hmac, computed_hmac)) {
        throw new KeystoreSignatureException(
          `Hash mismatch; incorrect keystore password?`
        );
      }

      return new BksKeyStore(store_type, entries, version);
    } catch (error) {
      throw new BadKeystoreFormatException(error.message);
    }
  }

  /**
   *
   * @param {Buffer} data
   * @param {string} store_type
   * @param {string} store_password
   * @param {boolean} try_decrypt_keys
   * @returns {[object, number]}
   */
  static _load_bks_entries(
    data,
    store_type,
    store_password,
    try_decrypt_keys = false
  ) {
    const entries = {};
    let pos = 0;
    while (pos < data.length) {
      const entry_type = data.readUInt8(pos);
      pos += 1;
      if (entry_type === 0) break;

      const [alias, newPos1] = BksKeyStore._read_utf(data, pos);
      pos = newPos1;
      const timestamp = data.readBigUInt64BE(pos);
      pos += 8;
      const chain_length = data.readUInt32BE(pos);
      pos += 4;

      const cert_chain = [];
      for (let n = 0; n < chain_length; n++) {
        const [entry, newPos2] = BksKeyStore._read_bks_cert(
          data,
          pos,
          store_type
        );
        cert_chain.push(entry);
        pos = newPos2;
      }

      let entry;
      if (entry_type === ENTRY_TYPE_CERTIFICATE) {
        [entry, pos] = BksKeyStore._read_bks_cert(data, pos, store_type);
      } else if (entry_type === ENTRY_TYPE_KEY) {
        [entry, pos] = BksKeyStore._read_bks_key(data, pos, store_type);
      } else if (entry_type === ENTRY_TYPE_SECRET) {
        [entry, pos] = BksKeyStore._read_bks_secret(data, pos, store_type);
      } else if (entry_type === ENTRY_TYPE_SEALED) {
        [entry, pos] = BksKeyStore._read_bks_sealed(data, pos, store_type);
      } else {
        throw new BadKeystoreFormatException(
          `Unexpected keystore entry type ${entry_type}`
        );
      }

      entry.alias = alias;
      entry.timestamp = timestamp;
      entry.cert_chain = cert_chain;

      if (try_decrypt_keys) {
        try {
          entry.decrypt(store_password);
        } catch {
          // Let user call .decrypt() manually afterwards
        }
      }

      if (alias in entries) {
        throw new DuplicateAliasException(`Found duplicate alias '${alias}'`);
      }
      entries[alias] = entry;
    }
    return [entries, pos];
  }

  static _read_bks_cert(data, pos, store_type) {
    const [cert_type, newPos1] = BksKeyStore._read_utf(data, pos);
    pos = newPos1;
    const [cert_data, newPos2] = BksKeyStore._read_data(data, pos);
    pos = newPos2;
    return [
      new BksTrustedCertEntry({ type: cert_type, cert: cert_data, store_type }),
      pos,
    ];
  }

  /**
   *
   * @param {Buffer} data
   * @param {number} pos
   * @param {string} store_type
   * @returns
   */
  static _read_bks_key(data, pos, store_type) {
    const key_type = data.readUInt8(pos);
    pos += 1;
    const [key_format, newPos1] = BksKeyStore._read_utf(data, pos);
    pos = newPos1;
    const [key_algorithm, newPos2] = BksKeyStore._read_utf(data, pos);
    pos = newPos2;
    const [key_enc, newPos3] = BksKeyStore._read_data(data, pos);
    pos = newPos3;
    return [
      new BksKeyEntry(key_type, key_format, key_algorithm, key_enc, {
        store_type,
      }),
      pos,
    ];
  }

  static _read_bks_secret(data, pos, store_type) {
    const [secret_data, newPos] = BksKeyStore._read_data(data, pos);
    pos = newPos;
    return [new BksSecretKeyEntry({ store_type, encrypted: secret_data }), pos];
  }

  static _read_bks_sealed(data, pos, store_type) {
    const [sealed_data, newPos] = BksKeyStore._read_data(data, pos);
    pos = newPos;
    return [new BksSealedKeyEntry({ store_type, encrypted: sealed_data }), pos];
  }

  /**
   *
   * @param {Buffer} data
   * @param {number} pos
   * @returns {[string, number]} utfData, newPos
   */
  static _read_utf(data, pos) {
    const length = data.readUInt16BE(pos);
    pos += 2;
    const utfData = data.subarray(pos, pos + length).toString("utf8");
    pos += length;
    return [utfData, pos];
  }

  /**
   *
   * @param {Buffer} data
   * @param {number} pos
   * @returns {[Buffer, number]}
   */
  static _read_data(data, pos) {
    const length = data.readUInt32BE(pos);
    pos += 4;
    const result = data.subarray(pos, pos + length);
    pos += length;
    return [result, pos];
  }
}

export class UberKeyStore extends BksKeyStore {
  /**
   *
   * @param {Buffer} data
   * @param {string} store_password
   * @param {boolean} try_decrypt_keys
   * @returns
   */
  static loads(data, store_password, try_decrypt_keys = true) {
    try {
      let pos = 0;
      const version = data.readUInt32BE(pos);
      pos += 4;
      if (version !== 1) {
        throw new UnsupportedKeystoreVersionException(
          `Unsupported UBER keystore version; only v1 supported, found v${version}`
        );
      }

      const [salt, newPos] = BksKeyStore._read_data(data, pos);
      pos = newPos;
      const iteration_count = data.readUInt32BE(pos);
      pos += 4;
      const encrypted_bks_store = data.subarray(pos);

      let decrypted;
      try {
        decrypted = UberKeyStore._decrypt_PBEWithSHAAndTwofishCBC(
          encrypted_bks_store,
          store_password,
          salt,
          iteration_count
        );
      } catch (error) {
        throw new DecryptionFailureException(
          `Failed to decrypt UBER keystore: bad password?`
        );
      }

      const hash_fn = createHash("sha1");
      const hash_digest_size = hash_fn.digest().length;

      const bks_store = decrypted.subarray(0, -hash_digest_size);
      const bks_hash = decrypted.subarray(-hash_digest_size);
      if (bks_hash.length !== hash_digest_size) {
        throw new BadKeystoreFormatException(
          `Insufficient signature bytes; found ${bks_hash.length} bytes, expected ${hash_digest_size} bytes`
        );
      }
      if (!timingSafeEqual(hash_fn.update(bks_store).digest(), bks_hash)) {
        throw new KeystoreSignatureException(
          `Hash mismatch; incorrect keystore password?`
        );
      }

      const store_type = "uber";
      const [entries, size] = BksKeyStore._load_bks_entries(
        bks_store,
        store_type,
        store_password,
        try_decrypt_keys
      );
      return new UberKeyStore(store_type, entries, version);
    } catch (error) {
      throw new BadKeystoreFormatException(error.message);
    }
  }

  static _decrypt_PBEWithSHAAndTwofishCBC(
    data,
    password,
    salt,
    iteration_count
  ) {
    const key_length = 32; // 256 bits
    const iv_length = 16; // 128 bits

    // Derive key and IV from password and salt
    const key = pbkdf2Sync(
      password,
      salt,
      iteration_count,
      key_length + iv_length,
      "sha1"
    );
    const derived_key = key.subarray(0, key_length);
    const iv = key.subarray(key_length);

    const decipher = createDecipheriv("twofish-cbc", derived_key, iv);
    decipher.setAutoPadding(true);

    let decrypted = decipher.update(data);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
  }

  constructor(store_type, entries, version = 1) {
    super(store_type, entries, version);
  }
}
