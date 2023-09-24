const Cryptic = require('../cryptic.js');

const STOREAGE_SALT = 'cloud robot resist squeeze';

async function main() {
  const testMessage = 'what is the air speed velocity of an unladen swallow?';
  const cw = Cryptic.encryptString('foobar', STOREAGE_SALT);
  const iv = cw.getInitVector();
  const encrypted = await cw.encrypt(testMessage, iv);
  const decrypted = await cw.decrypt(encrypted, iv);

  console.log('Encrypted Test', [encrypted]);

  console.log('Decrypted Test', [decrypted]);

  console.log('Copyable to Browser', [
    `${encrypted}:${Cryptic.bufferToHex(iv)}`,
  ]);

  let valFromBrowser =
    'af9c8ba7e4d173c47e03cd21fcb28cb5b1cf765482a98f1e41c9eb18:f7ab6dc9bec87277f447cbd8168672ae';
  let [data, biv] = valFromBrowser.split(':');

  console.log('Decrypt value from Browser', [
    data,
    biv,
    await cw.decrypt(data, biv),
  ]);

  // let badIV = '2830ee00182b3113bab6427158c22677'

  // try {
  //   let wontDecrypt = await cw.decrypt(data, badIV)

  //   console.log(
  //     'Test from Browser with bad IV; this should not show',
  //     [
  //       badIV,
  //       wontDecrypt,
  //     ]
  //   )
  // } catch(err) {
  //   console.error(
  //     '\x1b[91m[failed] Test from Browser with bad IV\x1b[0m',
  //     {
  //       badIV,
  //       err
  //     }
  //   )
  // }
}

main();
