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
 *
 * @typedef {Object} StorageCryptic
 * @prop {EncryptStorage} encrypt
 * @prop {DecryptStorage} decrypt
 * @prop {InitVector} getInitVector
 */

/**
 * @callback InitVector
 *
 * @returns {ArrayBuffer}
 */

/**
 * @callback EncryptStorage
 *
 * @param {string} message
 * @param {string | ArrayBufferLike} iv
 *
 * @returns {Promise<string>}
 */

/**
 * @callback DecryptStorage
 *
 * @param {string} ciphertext
 * @param {string | ArrayBufferLike} iv
 *
 * @returns {Promise<string>}
 */

/**
 * @callback BufferToString
 *
 * @param {ArrayBufferLike} ab
 */

/**
 * @callback StringToBuffer
 *
 * @param {String} str
 */

/**
 * @callback ToHex
 *
 * @param {Uint8Array} bytes
 *
 * @returns {String} - hex
 */

/**
 * @callback ToBytes
 *
 * @param {String} hex
 *
 * @returns {Uint8Array}
 */

/**
 * @callback BufferToHex
 *
 * @param {ArrayBufferLike} buf
 */

/**
 * @callback HexToBuffer
 *
 * @param {String} hex
 *
 * @returns {ArrayBufferLike}
 */

/**
 * @callback BrowserSupport
 *
 * @returns {Promise<Boolean>}
 */

/**
 * @async
 * @callback EncryptedStorage
 *
 * @param {Storage} storage
 * @param {String | StorageCryptic} arg1
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
 * @param {StorageCryptic} cryptoWrapper Crypto
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

/**
 * Creates an instance of CrypticStorage with encrypt and decrypt operations
 *
 * @callback EncryptString
 * @param {String} password
 * @param {String} salt
 * @param {Crypto} [currentCrypto] - window.crypto instance
 * @returns {StorageCryptic}
 */

/** @type {CrypticStorage} */
// @ts-ignore
var CrypticStorage = ('object' === typeof module && exports) || {};

(function (window, CrypticStorage) {
  'use strict';

  let Crypto = window.crypto || require('node:crypto');

  CrypticStorage.bufferToString = function (ab) {
    let bytes = new Uint8Array(ab);
    let str = new TextDecoder().decode(bytes);

    return str;
  };

  CrypticStorage.stringToBuffer = function (str) {
    let bytes = new TextEncoder().encode(str);

    return bytes.buffer;
  };

  CrypticStorage.toHex = function (bytes) {
    /** @type {Array<String>} */
    let hex = [];

    bytes.forEach(function (b) {
      let h = b.toString(16);
      h = h.padStart(2, '0');
      hex.push(h);
    });

    return hex.join('');
  };

  CrypticStorage.toBytes = function (hex) {
    let len = hex.length / 2;
    let bytes = new Uint8Array(len);

    let index = 0;
    for (let i = 0; i < hex.length; i += 2) {
      let c = hex.slice(i, i + 2);
      let b = parseInt(c, 16);
      bytes[index] = b;
      index += 1;
    }

    return bytes;
  };

  CrypticStorage.bufferToHex = function (buf) {
    let bytes = new Uint8Array(buf);
    let hex = CrypticStorage.toHex(bytes);
    return hex;
  };

  CrypticStorage.hexToBuffer = function (hex) {
    let bytes = CrypticStorage.toBytes(hex);
    return bytes.buffer;
  };

  CrypticStorage.encryptString = function (
    password,
    salt,
    currentCrypto = Crypto,
  ) {
    const name = 'AES-GCM';
    const targets = ['encrypt', 'decrypt'];
    const pbkdfName = 'PBKDF2';
    const hash = { name: 'SHA-256', length: 256 };
    const iterations = 1000;

    const deriveKey = async (password, salt, currentCrypto = Crypto) => {
      const keyMaterial = await currentCrypto.subtle.importKey(
        'raw',
        CrypticStorage.stringToBuffer(password),
        { name: pbkdfName },
        false,
        ['deriveBits', 'deriveKey'],
      );
      return currentCrypto.subtle.deriveKey(
        {
          name: pbkdfName,
          salt: CrypticStorage.stringToBuffer(salt),
          iterations,
          hash: hash.name,
        },
        keyMaterial,
        { name, length: hash.length },
        true,
        // @ts-ignore
        targets,
      );
    };

    async function encrypt(message, iv) {
      if ('string' === typeof iv) {
        iv = CrypticStorage.hexToBuffer(iv);
      }

      return await deriveKey(password, salt)
        .then(
          async (cryptoKey) =>
            await currentCrypto.subtle.encrypt(
              { name, iv },
              cryptoKey,
              CrypticStorage.stringToBuffer(message),
            ),
        )
        .then((enc) => CrypticStorage.bufferToHex(enc));
    }

    async function decrypt(ciphertext, iv) {
      if ('string' === typeof iv) {
        iv = CrypticStorage.hexToBuffer(iv);
      }

      return await deriveKey(password, salt)
        .then(async function (cryptoKey) {
          return await currentCrypto.subtle.decrypt(
            { name, iv },
            cryptoKey,
            CrypticStorage.hexToBuffer(ciphertext),
          );
        })
        .then((dec) => CrypticStorage.bufferToString(dec));
    }

    function getInitVector() {
      return currentCrypto.getRandomValues(new Uint8Array(16));
    }

    return { encrypt, decrypt, getInitVector };
  };

  CrypticStorage.isBrowserSupported = async () => {
    const testMessage = 'w?';
    try {
      const cw = CrypticStorage.encryptString('a', 'b');
      const iv = cw.getInitVector();
      const encrypted = await cw.encrypt(testMessage, iv);
      const decrypted = await cw.decrypt(encrypted, iv);

      return decrypted === testMessage;
    } catch (error) {
      console.warn('Your browser does not support WebCrypto API', error);
      return false;
    }
  };

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
        return CrypticStorage.hexToBuffer(ivk);
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
        isSupported = await CrypticStorage.isBrowserSupported();
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
              `${encrypted}:${CrypticStorage.bufferToHex(iv)}`,
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
      CrypticStorage.encryptString(password, salt),
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
  window.CrypticStorage = CrypticStorage;
})(/** @type {Window} */ (globalThis.window || {}), CrypticStorage);

if ('object' === typeof module) {
  module.exports = CrypticStorage;
}
