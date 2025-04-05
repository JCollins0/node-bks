import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

// Function to encrypt data
function encryptWith3DES_CBC(data, key, iv) {
  const cipher = createCipheriv("des-ede3-cbc", key, iv);
  let encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return encrypted;
}

// Function to decrypt data
function decryptWith3DES_CBC(encryptedData, key, iv) {
  const decipher = createDecipheriv("des-ede3-cbc", key, iv);
  let decrypted = Buffer.concat([
    decipher.update(encryptedData),
    decipher.final(),
  ]);
  return decrypted.toString();
}

describe("3DES CBC Encryption/Decryption", () => {
  test("should encrypt and decrypt data correctly", () => {
    const data = "This is a test message"; // The data to encrypt
    let key = randomBytes(24); // 24-byte key for 3DES
    let iv = randomBytes(8); // 8-byte IV for CBC mode
    iv = Buffer.from("3454b76672f8a8f1", "hex");
    key = Buffer.from(
      "fe5c34ad93735f05a3c28cd836a830f4ab8c32370acadf0e",
      "hex"
    );

    // Encrypt the data
    const encrypted = encryptWith3DES_CBC(data, key, iv);

    // Decrypt the data
    const decrypted = decryptWith3DES_CBC(encrypted, key, iv);

    // Validate the decryption
    expect(decrypted).toBe(data);
  });
});
