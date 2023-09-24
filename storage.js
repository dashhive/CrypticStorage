/**
 * @typedef {import('./cryptic.js').StringCryptic} StringCryptic
 * @typedef {import('./cryptic.js').BufferToString} BufferToString
 * @typedef {import('./cryptic.js').StringToBuffer} StringToBuffer
 * @typedef {import('./cryptic.js').ToHex} ToHex
 * @typedef {import('./cryptic.js').ToBytes} ToBytes
 * @typedef {import('./cryptic.js').BufferToHex} BufferToHex
 * @typedef {import('./cryptic.js').HexToBuffer} HexToBuffer
 * @typedef {import('./cryptic.js').EncryptString} EncryptString
 * @typedef {import('./cryptic.js').BrowserSupport} BrowserSupport
 * @typedef {import('./cryptic.js').Cryptic} Cryptic
 */

/**
 * @typedef CrypticStorage
 * @prop {BufferToString} bufferToString
 * @prop {StringToBuffer} stringToBuffer
 * @prop {ToHex} toHex
 * @prop {ToBytes} toBytes
 * @prop {BufferToHex} bufferToHex
 * @prop {HexToBuffer} hexToBuffer
 * @prop {EncryptedStorage} getEncryptedStorage
 * @prop {EncryptedStorageFromPassword} getEncryptedStorageFromPassword
 * @prop {EncryptedStorageFromCrypto} getEncryptedStorageFromCrypto
 * @prop {EncryptString} encryptString
 * @prop {BrowserSupport} isBrowserSupported
 */

/**
 * @async
 * @callback EncryptedStorage
 *
 * @param {Storage} storage
 * @param {String | StringCryptic} arg1
 * @param {String} arg2
 *
 * @returns {Promise<EncryptedStorageFromCrypto | EncryptedStorageFromPassword>}
 */

/**
 * Gets encrypted storage with async getItem and setItem
 *
 * @async
 * @callback EncryptedStorageFromCrypto
 *
 * @param {Storage} storage Browser storage - localStorage, sessionStorage
 * @param {StringCryptic} cryptoWrapper Crypto
 */

/**
 * @async
 * @callback EncryptedStorageFromPassword
 *
 * @param {Storage} storage
 * @param {String} password
 * @param {String} salt
 *
 * @returns {Promise<EncryptedStorageFromCrypto>}
 */

/** @type {CrypticStorage} */
// @ts-ignore
var CrypticStorage = ('object' === typeof module && exports) || {};

(function (Window, CrypticStorage) {
  'use strict';

  /** @type {Cryptic} */
  // @ts-ignore
  let { Cryptic } = Window;

  CrypticStorage.getEncryptedStorageFromCrypto = async function (
    storage,
    cryptoWrapper,
  ) {
    let isSupported;

    /**
     *
     * @param {String} [key]
     * @returns {ArrayBufferLike}
     */
    const getIV = (key) => {
      let ivk = storage.getItem(key);

      if (ivk) {
        ivk = ivk.split(':')[1];
        return Cryptic.hexToBuffer(ivk);
      }

      return cryptoWrapper.getInitVector();
    };

    const unmodifiedFunctions = {
      clear() {
        storage.clear();
      },
      get length() {
        return storage.length;
      },
      key(i) {
        return storage.key(i);
      },
    };

    const setBrowserSupport = async () => {
      if (typeof isSupported === 'undefined') {
        isSupported = await Cryptic.isBrowserSupported();
      }
    };

    await setBrowserSupport();

    return {
      ...storage,
      async setItem(key, value) {
        await setBrowserSupport();
        if (isSupported) {
          try {
            const iv = getIV(key);
            const encrypted = await cryptoWrapper.encrypt(value, iv);

            storage.setItem(
              key,
              `${encrypted}:${Cryptic.bufferToHex(iv)}`,
            );
          } catch (error) {
            console.error(`Cannot set encrypted value for ${key}`, error);
            throw error;
          }
        } else {
          storage.setItem(key, value); // legacy mode, no encryption
        }
      },
      async getItem(key) {
        await setBrowserSupport();
        if (isSupported) {
          try {
            const [data, iv] = storage.getItem(key)?.split(':');

            return await cryptoWrapper.decrypt(data, iv);
          } catch (error) {
            console.error(`Cannot get encrypted item for ${key}.`, error);
            return null;
          }
        }
        return storage.getItem(key); // legacy mode, no encryption
      },
      async removeItem(key) {
        storage.removeItem(key);
      },
      ...unmodifiedFunctions,
    };
  };

  CrypticStorage.getEncryptedStorageFromPassword = async function (
    storage,
    password,
    salt,
  ) {
    return await CrypticStorage.getEncryptedStorageFromCrypto(
      storage,
      Cryptic.encryptString(password, salt),
    );
  };

  CrypticStorage.getEncryptedStorage = async function (storage, ...args) {
    const [arg1, arg2] = args;
    if (typeof arg1 === 'object') {
      // it is crypto object
      return await CrypticStorage.getEncryptedStorageFromCrypto(storage, arg1);
    }
    if (typeof arg1 === 'string' && typeof arg2 === 'string') {
      return await CrypticStorage.getEncryptedStorageFromPassword(
        storage,
        arg1,
        arg2,
      );
    }
  };

  // @ts-ignore
  Window.CrypticStorage = CrypticStorage;
})(
  /** @type {Window} */ (globalThis?.window || globalThis || {}),
  CrypticStorage
);

if ('object' === typeof module) {
  module.exports = CrypticStorage;
}
