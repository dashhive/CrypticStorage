# Cryptic Storage

### Browser & Server compatible encrypted storage

Cryptic is a thin wrapper around Web Crypto and sets sane defaults to allow quickly implementing encryption in your application.

### Getting Started
Install `crypticstorage` via NPM

```sh
npm install crypticstorage
```

### Example

```js
// Simple example

// import '../node_modules/crypticstorage/cryptic.js';
import { Cryptic } from 'crypticstorage';

const salt = Cryptic.bufferToHex(Cryptic.randomBytes(32))
const iv = Cryptic.bufferToHex(Cryptic.randomBytes(16))

const cryptic = Cryptic.create(
  decryptPass,
  salt,
)

let encryptedText = await cryptic.encrypt(
  'text to encrypt',
  iv,
);

console.log('Encrypted Text', encryptedText)

let decryptedText = await cryptic.decrypt(
  encryptedText,
  iv,
);

console.log('Decrypted Text', decryptedText)
```

## Breaking Changes

**Deprecation warning**: `Cryptic.encryptString` renamed to `Cryptic.create`

**Breaking Change**: `Cryptic.encryptString` now expects `salt` in HEX format instead of a string. If stored as plain string, convert with the example below.

```js
const cryptic = Cryptic.create(
  encryptPass,
  Cryptic.bufferToHex(
    Cryptic.stringToBuffer(salt)
  )
)
```