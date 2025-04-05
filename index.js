import { BksKeyStore } from "./src/bks.js";
import { AbstractKeystore } from "./src/classes.js";

/**
 *
 * @param {string} keystorePath
 * @param {string} password
 * @returns {Promise.<BksKeyStore>} bksKeyStore
 */
export function readBKSFile(keystorePath, password) {
  return new Promise(async (resolve, reject) => {
    try {
      const keystore = await BksKeyStore.load(keystorePath, password);
      resolve(keystore);
    } catch (error) {
      reject(error);
    }
  });
}

/**
 *
 * @param {AbstractKeystore} keystore
 */
export function printBksEntries(keystore, custom_alias_passwords = {}) {
  for (const alias in keystore.entries) {
    const entry = keystore.entries[alias];
    if (alias in custom_alias_passwords) {
      entry.decrypt(custom_alias_passwords[alias]);
    }
    console.log(alias, entry);
  }
}
