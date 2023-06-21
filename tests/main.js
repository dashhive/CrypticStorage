import '../crypticStorage.js';
import * as CrypticStorageTypes from '../crypticStorage.js';

const STOREAGE_SALT = 'cloud robot resist squeeze'

/** @type {CrypticStorageTypes} */
let CrypticStorage = window?.CrypticStorage || globalThis?.CrypticStorage
let encryptedStore
let passphrase

async function initEncryptedStore(pass) {
  let tmpStore = await CrypticStorage.getEncryptedStorage(
    localStorage,
    pass,
    STOREAGE_SALT,
  )
  if (passphrase !== pass || !encryptedStore) {
    encryptedStore = tmpStore
  }
  passphrase = pass
  return encryptedStore
}

let $s = await initEncryptedStore('pass')

window.$s = $s // expose to window global

await $s.setItem('test_one', 'this should be encrypted')

console.log('First Test Encrypted', [
  localStorage.getItem('test_one')
])

console.log('Decrypt First Test', [
  await $s.getItem('test_one')
])
