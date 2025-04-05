import { createHash, getHashes } from "crypto";
import { UnsupportedAlgorithmException } from "./errors.js";

export function createHashAlgorithm(algorithm) {
  if (getHashes().includes(algorithm)) {
    switch (algorithm) {
      case "sha1":
        return new SHA1();
      default:
        throw new UnsupportedAlgorithmException(
          `Library Unsupported hash algorithm: ${algorithm}`
        );
    }
  } else {
    throw new UnsupportedAlgorithmException(
      `Node Unsupported hash algorithm: ${algorithm}`
    );
  }
}

export class AbstractHashAlgorithm {
  constructor(algorithm, block_size) {
    this._hash = createHash(algorithm);
    this._block_size = block_size;
  }

  digest() {
    return this._hash.digest();
  }

  block_size() {
    return this._block_size;
  }

  hash() {
    return this._hash;
  }

  update(data) {
    this._hash.update(data);
    return this;
  }
}

export class SHA1 extends AbstractHashAlgorithm {
  constructor() {
    super("sha1", 64);
  }
}
