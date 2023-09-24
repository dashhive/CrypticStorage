/**
 * @typedef Cryptic
 * @prop {SetConfig} setConfig
 * @prop {BufferToString} bufferToString
 * @prop {StringToBuffer} stringToBuffer
 * @prop {ToHex} toHex
 * @prop {ToBytes} toBytes
 * @prop {BufferToHex} bufferToHex
 * @prop {HexToBuffer} hexToBuffer
 * @prop {EncryptString} encryptString
 * @prop {BrowserSupport} isBrowserSupported
 *
 * @typedef {Object} StringCryptic
 * @prop {EncryptStr} encrypt
 * @prop {DecryptStr} decrypt
 * @prop {InitVector} getInitVector
 */

/**
 * @callback SetConfig
 *
 * @param {string | any} key
 * @param {string} value
 */

/**
 * @callback InitVector
 *
 * @returns {ArrayBuffer}
 */

/**
 * @callback EncryptStr
 *
 * @param {string} message
 * @param {string | ArrayBufferLike} iv
 *
 * @returns {Promise<string>}
 */

/**
 * @callback DecryptStr
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
 * Creates an instance of Cryptic with encrypt and decrypt operations
 *
 * @callback EncryptString
 * @param {String} password
 * @param {String} salt
 * @param {Crypto} [currentCrypto] - window.crypto instance
 * @returns {StringCryptic}
 */

/** @type {Cryptic} */
// @ts-ignore
var Cryptic = ('object' === typeof module && exports) || {};

(function (Window, Cryptic) {
  'use strict';

  let Crypto = Window.crypto;

  let defaultConfig = {
    name: 'AES-GCM',
    targets: ['encrypt', 'decrypt'],
    pbkdfName: 'PBKDF2',
    hash: { name: 'SHA-256', length: 256 },
    iterations: 1000,
  }

  Cryptic.setConfig = function (key, value) {
    if (key && !value) {
      defaultConfig = {
        ...defaultConfig,
        ...key,
      }
    }
    if (key && value) {
      defaultConfig[key] = value
    }

    return defaultConfig;
  };

  Cryptic.bufferToString = function (ab) {
    let bytes = new Uint8Array(ab);
    let str = new TextDecoder().decode(bytes);

    return str;
  };

  Cryptic.stringToBuffer = function (str) {
    let bytes = new TextEncoder().encode(str);

    return bytes.buffer;
  };

  Cryptic.toHex = function (bytes) {
    /** @type {Array<String>} */
    let hex = [];

    bytes.forEach(function (b) {
      let h = b.toString(16);
      h = h.padStart(2, '0');
      hex.push(h);
    });

    return hex.join('');
  };

  Cryptic.toBytes = function (hex) {
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

  Cryptic.bufferToHex = function (buf) {
    let bytes = new Uint8Array(buf);
    let hex = Cryptic.toHex(bytes);
    return hex;
  };

  Cryptic.hexToBuffer = function (hex) {
    let bytes = Cryptic.toBytes(hex);
    return bytes.buffer;
  };

  Cryptic.encryptString = function (
    password,
    salt,
    currentCrypto = Crypto,
  ) {
    let encryptionPassword = password
    // const name = 'AES-GCM';
    // const targets = ['encrypt', 'decrypt'];
    // const pbkdfName = 'PBKDF2';
    // const hash = { name: 'SHA-256', length: 256 };
    // const iterations = 1000;

    const deriveKey = async (
      password,
      salt,
      currentCrypto = Crypto
    ) => {
      const keyMaterial = await currentCrypto.subtle.importKey(
        'raw',
        Cryptic.stringToBuffer(password),
        defaultConfig.pbkdfName,
        false,
        ['deriveBits', 'deriveKey'],
      );
      return currentCrypto.subtle.deriveKey(
        {
          name: defaultConfig.pbkdfName,
          salt: Cryptic.stringToBuffer(salt),
          iterations: defaultConfig.iterations,
          hash: defaultConfig.hash.name,
        },
        keyMaterial,
        {
          name: defaultConfig.name,
          length: defaultConfig.hash.length
        },
        true,
        // @ts-ignore
        defaultConfig.targets,
      );
    };

    async function encrypt(message, iv) {
      if ('string' === typeof iv) {
        iv = Cryptic.hexToBuffer(iv);
      }

      return await deriveKey(encryptionPassword, salt)
        .then(
          async (cryptoKey) =>
            await currentCrypto.subtle.encrypt(
              { name: defaultConfig.name, iv },
              cryptoKey,
              Cryptic.stringToBuffer(message),
            ),
        )
        .then((enc) => Cryptic.bufferToHex(enc))
    }

    async function decrypt(ciphertext, iv) {
      if ('string' === typeof iv) {
        iv = Cryptic.hexToBuffer(iv);
      }

      return await deriveKey(encryptionPassword, salt)
        .then(async function (cryptoKey) {
          return await currentCrypto.subtle.decrypt(
            { name: defaultConfig.name, iv },
            cryptoKey,
            Cryptic.hexToBuffer(ciphertext),
          );
        })
        .then((dec) => Cryptic.bufferToString(dec))
    }

    function getInitVector() {
      return currentCrypto.getRandomValues(new Uint8Array(16));
    }

    return { encrypt, decrypt, getInitVector };
  };

  Cryptic.isBrowserSupported = async () => {
    const testMessage = 'w?';
    try {
      const cw = Cryptic.encryptString('a', 'b');
      const iv = cw.getInitVector();
      const encrypted = await cw.encrypt(testMessage, iv);
      const decrypted = await cw.decrypt(encrypted, iv);

      return decrypted === testMessage;
    } catch (error) {
      console.warn('Your browser does not support WebCrypto API', error);
      return false;
    }
  };

  // @ts-ignore
  Window.Cryptic = Cryptic;
})(
  /** @type {Window} */ (globalThis?.window || globalThis || {}),
  Cryptic
);

if ('object' === typeof module) {
  module.exports = Cryptic;
}
