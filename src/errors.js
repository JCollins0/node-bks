export class BadPaddingException extends Error {
  constructor(message) {
    super(message);
    this.name = "BadPaddingException";
  }
}
export class BadHashCheckException extends Error {
  constructor(message) {
    super(message);
    this.name = "BadHashCheckException";
  }
}
export class BadKeystoreFormatException extends Error {
  constructor(message) {
    super(message);
    this.name = "BadKeystoreFormatException";
  }
}
export class DecryptionFailureException extends Error {
  constructor(message) {
    super(message);
    this.name = "DecryptionFailureException";
  }
}
export class UnexpectedAlgorithmException extends Error {
  constructor(message) {
    super(message);
    this.name = "UnexpectedAlgorithmException";
  }
}
export class NotYetDecryptedException extends Error {
  constructor(message) {
    super(message);
    this.name = "NotYetDecryptedException";
  }
}
export class UnsupportedKeyFormatException extends Error {
  constructor(message) {
    super(message);
    this.name = "UnsupportedKeyFormatException";
  }
}
export class ValueError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValueError";
  }
}
export class UnsupportedAlgorithmException extends Error {
  constructor(message) {
    super(message);
    this.name = "UnsupportedAlgorithmException";
  }
}
export class BadDataLengthException extends Error {
  constructor(message) {
    super(message);
    this.name = "BadDataLengthException";
  }
}
export class UnexpectedKeyEncodingException extends Error {
  constructor(message) {
    super(message);
    this.name = "UnexpectedKeyEncodingException";
  }
}
export class UnsupportedKeystoreVersionException extends Error {
  constructor(message) {
    super(message);
    this.name = "UnsupportedKeystoreVersionException";
  }
}
export class KeystoreSignatureException extends Error {
  constructor(message) {
    super(message);
    this.name = "KeystoreSignatureException";
  }
}
export class NotImplementedError extends Error {
  constructor(message) {
    super(message);
    this.name = "NotImplementedError";
  }
}

export class DuplicateAliasException extends Error {
  constructor(message) {
    super(message);
    this.name = "DuplicateAliasException";
  }
}
