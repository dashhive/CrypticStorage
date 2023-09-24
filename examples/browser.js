// import '../dist/cryptic.js';
// import '../dist/crypticstorage.js';
import '../dist/index.js';
// import * as CrypticTypes from '../cryptic.js';
// import * as CrypticStorageTypes from '../crypticstorage.js';

const STOREAGE_SALT = 'cloud robot resist squeeze';

// /** @type {CrypticTypes} */
let Cryptic = window?.Cryptic || globalThis?.Cryptic;
// /** @type {CrypticStorageTypes} */
let CrypticStorage = window?.CrypticStorage || globalThis?.CrypticStorage;

let encryptedStore;
let passphrase;
let $s;
let $c;
let iv;

let encryptMsgForm = document.getElementById('encrypt')
let decryptMsgForm = document.getElementById('decrypt')
let msgField = document.getElementById('message')
let encMsgField = document.getElementById('encryptedMessage')
let encVectorField = document.getElementById('encryptedVector')

async function initEncryptedStore(pass) {
  $c = Cryptic.encryptString(pass, STOREAGE_SALT);
  iv = Cryptic.bufferToHex($c.getInitVector());
  encVectorField.value = iv

  let tmpStore = await CrypticStorage.getEncryptedStorage(
    localStorage,
    pass,
    STOREAGE_SALT,
  );
  if (passphrase !== pass || !encryptedStore) {
    encryptedStore = tmpStore;
  }
  passphrase = pass;

  return {
    $store: encryptedStore,
    $wrapper: $c,
    $iv: iv,
  };
}

let $ies = await initEncryptedStore('pass');

$s = $ies.$store
$c = $ies.$wrapper

window.$s = $ies.$store; // expose to window global
window.$c = $ies.$wrapper; // expose to window global

await $s.setItem('test_one', 'this should be encrypted');

console.log('First Test Encrypted', [localStorage.getItem('test_one')]);

console.log('Decrypt First Test', [await $s.getItem('test_one')]);

document.addEventListener('change', async event => {
  let { name, value } = event?.target
  console.log(
    'form change event', name, event,
  )

  if (name === 'pass') {
    $ies = await initEncryptedStore(
      value
    );
    $s = $ies.$store
    $c = $ies.$wrapper
    iv = $ies.$iv

    window.$s = $ies.$store; // expose to window global
    window.$c = $ies.$wrapper; // expose to window global

    if (msgField.value) {
      const encrypted = await $c.encrypt(
        msgField.value, iv
      );

      encMsgField.value = encrypted
    }

    encVectorField.value = iv
  }

  if (name === 'message') {
    const encrypted = await $c.encrypt(
      value, iv
    );

    encMsgField.value = encrypted
  }

  if (name === 'encryptedMessage') {
    if (value && iv) {
      try {
        const decrypted = await $c.decrypt(
          value, iv
        );

        msgField.value = decrypted
      } catch(err) {
        console.error('[failed] decrypt encryptedMessage', value, iv, err)
      }
    }
  }

  if (name === 'encryptedVector') {
    iv = value
    if (encMsgField.value) {
      try {
        const decrypted = await $c.decrypt(
          encMsgField.value, iv
        );

        msgField.value = decrypted
      } catch(err) {
        console.error('[failed] decrypt encryptedVector', encMsgField.value, iv, err)
      }
    }
  }
})

document.addEventListener('submit', async event => {
  event.preventDefault()
  event.stopPropagation()
  console.log('stop form submit event', event)
})
