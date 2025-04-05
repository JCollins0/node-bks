import { readBKSFile } from "../index.js";
import { describe, expect, test } from "@jest/globals";
import { BadKeystoreFormatException } from "../src/errors.js";
import { BksKeyStore } from "../src/bks.js";

describe("bks", () => {
  test("it should read the bks file", async () => {
    const data = await readBKSFile("./tests/files/christmas.bks", "12345678");
    expect(data).not.toBeNull();
    expect(data).not.toBeUndefined();
    expect(data).toBeInstanceOf(BksKeyStore);
  });

  test("it should not read the bks file with wrong password", () => {
    expect(
      readBKSFile("./tests/files/christmas.bks", "wrong_password")
    ).rejects.toThrow(BadKeystoreFormatException);
  });
});

// christmas.bks 12345678
// const keystorePath = "./tests/files/christmas.bks";
// const password = "12345678";
// const custom_alias_passwords = {
//   sealed_public_key: "public_password",
// };

// const bksKeyStore = await readBKSFile(keystorePath, password);
// printBksEntries(bksKeyStore, custom_alias_passwords);
