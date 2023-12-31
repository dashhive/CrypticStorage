/**
 * @typedef Cryptic
 * @prop {SetConfig} setConfig
 * @prop {BufferToString} bufferToString
 * @prop {StringToBuffer} stringToBuffer
 * @prop {ToHex} toHex
 * @prop {ToBytes} toBytes
 * @prop {BufferToHex} bufferToHex
 * @prop {HexToBuffer} hexToBuffer
 * @prop {CrypticInstance} create
 * @prop {EncryptString} encryptString - Deprecated: renamed to `create` since version 0.1.0
 * @prop {BrowserSupport} isBrowserSupported
 * @prop {RandomBytes} randomBytes
 *
 * @typedef {Object} CrypticMethods
 * @prop {Promise<CryptoKey>} keyMaterial
 * @prop {Promise<CryptoKey>} derivedKey
 * @prop {EncryptStr} encrypt
 * @prop {DecryptStr} decrypt
 * @prop {DeriveKey} deriveKey
 * @prop {DeriveBits} deriveBits
 * @prop {InitVector} getInitVector
 */

/**
 * @callback RandomBytes
 *
 * @param {number} bytes
 *
 * @returns {Uint8Array}
 */

/**
 * @callback SetConfig
 *
 * @param {string | any} key
 * @param {string | number} [value]
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
 * @param {Function} [outputFormatter]
 *
 * @returns {Promise<string>}
 */

/**
 * @callback DecryptStr
 *
 * @param {string} ciphertext
 * @param {string | ArrayBufferLike} iv
 * @param {Function} [outputFormatter]
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
 * Creates SubtleCrypto key material
 *
 * @callback ImportKey
 * @param {String} password
 * @param {Crypto} [currentCrypto] - window.crypto instance
 * @returns {Promise<CryptoKey>}
 */

/**
 * Derives a secret key from SubtleCrypto key material
 *
 * @callback DeriveKey
 * @param {String | ArrayBufferLike} salt
 * @param {Crypto} [currentCrypto] - window.crypto instance
 * @returns {Promise<CryptoKey>}
 */

/**
 * Derives an array of bits from SubtleCrypto key material
 *
 * @callback DeriveBits
 * @param {Number} numBits
 * @param {String | ArrayBufferLike} salt
 * @param {Crypto} [currentCrypto] - window.crypto instance
 * @returns {Promise<ArrayBuffer>}
 */

/**
 * Creates an instance of Cryptic with encrypt and decrypt operations
 *
 * @callback CrypticInstance
 * @param {String} password
 * @param {String} salt
 * @param {Crypto} [currentCrypto] - window.crypto instance
 * @returns {CrypticMethods}
 */

/**
 * Creates an instance of Cryptic with encrypt and decrypt operations
 *
 * @deprecated since version 0.1.0
 * @callback EncryptString
 * @param {String} password
 * @param {String} salt
 * @param {Crypto} [currentCrypto] - window.crypto instance
 * @returns {CrypticMethods}
 */


/** @type {Cryptic} */
// @ts-ignore
var Cryptic = ('object' === typeof module && exports) || {};

;(function (Window, Cryptic) {
  'use strict';

  let Crypto = Window.crypto

  let defaultConfig = {
    materialTargets: ['deriveBits', 'deriveKey'],
    deriveTargets: ['encrypt', 'decrypt'],
    derivationAlgorithm: 'PBKDF2',
    hashingAlgorithm: 'SHA-256',
    cipherAlgorithm: 'AES-GCM',
    cipherLength: 256,
    iterations: 262144,
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
  }

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
  }
  Cryptic.toHex = bytes => [...bytes].map(
    b => b.toString(16).padStart(2, '0')
  ).join('')
  Cryptic.bufferToString = ab => new TextDecoder().decode(new Uint8Array(ab))
  Cryptic.stringToBuffer = str => new TextEncoder().encode(str).buffer
  Cryptic.bufferToHex = buf => Cryptic.toHex(new Uint8Array(buf))
  Cryptic.hexToBuffer = hex => Cryptic.toBytes(hex).buffer
  Cryptic.randomBytes = (bytes = 16) => Crypto.getRandomValues(
    new Uint8Array(bytes)
  )

  Cryptic.create = function (
    password,
    salt,
    currentCrypto = Crypto,
  ) {
    let encryptionPassword = password

    async function importKey(
      password,
      currentCrypto = Crypto
    ) {
      return await currentCrypto.subtle.importKey(
        'raw',
        Cryptic.stringToBuffer(password),
        defaultConfig.derivationAlgorithm,
        false,
        // @ts-ignore
        defaultConfig.materialTargets,
      )
    }

    const keyMaterial = importKey(encryptionPassword, currentCrypto)

    async function deriveBits(
      numBits,
      salt,
      currentCrypto = Crypto
    ) {
      return await currentCrypto.subtle.deriveBits(
        {
          name: defaultConfig.derivationAlgorithm,
          salt: Cryptic.hexToBuffer(salt),
          iterations: defaultConfig.iterations,
          hash: defaultConfig.hashingAlgorithm,
        },
        await keyMaterial,
        numBits,
      )
    }

    async function deriveKey(
      salt,
      currentCrypto = Crypto
    ) {
      return await currentCrypto.subtle.deriveKey(
        {
          name: defaultConfig.derivationAlgorithm,
          salt: Cryptic.hexToBuffer(salt),
          iterations: defaultConfig.iterations,
          hash: defaultConfig.hashingAlgorithm,
        },
        await keyMaterial,
        {
          name: defaultConfig.cipherAlgorithm,
          length: defaultConfig.cipherLength,
        },
        true,
        // @ts-ignore
        defaultConfig.deriveTargets,
      )
    }

    const derivedKey = deriveKey(salt, currentCrypto)

    async function encrypt(
      message, iv,
      outputFormatter = Cryptic.bufferToHex
    ) {
      if ('string' === typeof iv) {
        iv = Cryptic.hexToBuffer(iv);
      }

      return await derivedKey
        .then(
          async (cryptoKey) =>
            await currentCrypto.subtle.encrypt(
              getCipherCfg(iv),
              cryptoKey,
              Cryptic.stringToBuffer(message),
            )
        )
        .then(outputFormatter)
    }

    async function decrypt(
      ciphertext, iv,
      outputFormatter = Cryptic.bufferToString
    ) {
      if ('string' === typeof iv) {
        iv = Cryptic.hexToBuffer(iv);
      }

      return await derivedKey
        .then(
          async cryptoKey =>
            await currentCrypto.subtle.decrypt(
              getCipherCfg(iv),
              cryptoKey,
              Cryptic.hexToBuffer(ciphertext),
            )
        )
        .then(outputFormatter)
    }

    function getCipherCfg(iv) {
      let cipherCfg = {
        name: defaultConfig.cipherAlgorithm,
      }

      if (defaultConfig.cipherAlgorithm === 'AES-GCM') {
        cipherCfg.iv = iv
      }

      if (defaultConfig.cipherAlgorithm === 'AES-CTR') {
        cipherCfg = {
          ...cipherCfg,
          counter: iv,
          length: defaultConfig.cipherLength
        }
      }

      return cipherCfg
    }

    function getInitVector() {
      return Cryptic.randomBytes(16);
    }

    return {
      keyMaterial, derivedKey,
      encrypt, decrypt, deriveBits, deriveKey, getInitVector,
    };
  };

  /**
   * @deprecated since version 0.1.0
   */
  Cryptic.encryptString = Cryptic.create; // deprecated

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
