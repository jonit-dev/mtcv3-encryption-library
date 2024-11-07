"use strict";
// Import necessary modules
Object.defineProperty(exports, "__esModule", { value: true });
const MTCV3_1 = require("./MTCV3");
// ------------------------------
// Example Usage
// ------------------------------
function example() {
    const password = 'strongpassword';
    const salt = 'somesalt';
    const mtc = new MTCV3_1.MTCv3(password, salt);
    const plaintext = 'HELLO WORLD';
    console.log('Plaintext:', plaintext);
    const ciphertext = mtc.encrypt(plaintext);
    console.log('Ciphertext (Hex):', ciphertext);
    const decrypted = mtc.decrypt(ciphertext);
    console.log('Decrypted Text:', decrypted);
    if (plaintext === decrypted) {
        console.log('Success: Decrypted text matches the original plaintext.');
    }
    else {
        console.error('Failure: Decrypted text does not match the original plaintext.');
    }
}
// Run the example
example();
