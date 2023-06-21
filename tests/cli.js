const CrypticStorage = require('../crypticstorage.js');

const STOREAGE_SALT = 'cloud robot resist squeeze';

async function main() {
  const testMessage = 'what is the air speed velocity of an unlaiden swallow?';
  const cw = CrypticStorage.encryptString('pass', STOREAGE_SALT);
  const iv = cw.getInitVector();
  const encrypted = await cw.encrypt(testMessage, iv);
  const decrypted = await cw.decrypt(encrypted, iv);

  console.log('Encrypted Test', [encrypted]);

  console.log('Decrypted Test', [decrypted]);

  console.log('Copyable to Browser', [
    `${encrypted}:${CrypticStorage.bufferToHex(iv)}`,
  ]);

  let valFromBrowser =
    '29c289446c1b007a1b10ff0fac3111cde2dca1bcd53cd0f4b5468f66aef0e526cddd1c371487d9c4:2830ee00182b3113bab4851258c22677';
  let [data, biv] = valFromBrowser.split(':');

  console.log('Encrypted Test from Browser', [
    biv,
    await cw.decrypt(data, biv),
  ]);

  // let badIV = '2830ee00182b3113bab6427158c22677'

  // console.log('Test from Browser with bad IV; should fail', [
  //   badIV,
  //   await cw.decrypt(data, badIV)
  // ])
}

main();
