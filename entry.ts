// Import necessary modules

import { MTCv3 } from './MTCV3';

// ------------------------------
// Example Usage
// ------------------------------

function example() {
  const password = 'SECRETKEY';
  const salt = 'UNIQUE_SALT';
  const plaintext = 'HELLO WORLD';

  const mtc = new MTCv3(password, salt, 10, 4); // 10 rounds, 4x4 matrix

  console.log('Plaintext:', plaintext);

  const ciphertext = mtc.encrypt(plaintext);
  console.log('Ciphertext (Hex):', ciphertext);

  const decrypted = mtc.decrypt(ciphertext);
  console.log('Decrypted Text:', decrypted);
}

// Run the example
example();
