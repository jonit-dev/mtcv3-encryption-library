# MTCv3 Encryption Library

![MIT License](https://img.shields.io/badge/license-MIT-green.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-green.svg)

**MTCv3** is a custom cryptographic encryption library inspired by the Advanced Encryption Standard (AES). It offers flexibility with customizable parameters, making it suitable for various encryption needs. The library is designed to provide block-based encryption with built-in modes like CBC, using AES-inspired transformations and customizable key schedules.

---

## **Table of Contents**

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Example](#basic-example)
  - [Custom Parameters](#custom-parameters)
- [API Documentation](#api-documentation)
- [Security Considerations](#security-considerations)
- [Performance](#performance)
- [Testing](#testing)
- [License](#license)

---

## **Features**

- **Block Cipher**: Implements a block cipher mode, similar to AES's CBC (Cipher Block Chaining).
- **Configurable Parameters**: Allows customization of rounds, matrix size, and key derivation parameters.
- **AES-Inspired Operations**: Uses AES S-Box substitutions, MixColumns-like mixing layer, and bit-level permutations.
- **Key Derivation**: Utilizes PBKDF2 with SHA-256 to derive keys from a password and salt.
- **CBC Mode Encryption**: Ensures data confidentiality across multiple blocks by using Cipher Block Chaining (CBC) mode.

---

## **Installation**

To install **MTCv3** in your Node.js project, run:

```bash
yarn add mtcv3-encryption
# or
npm install mtcv3-encryption
```

---

## **Usage**

### **Basic Example**

Here’s a quick example of using **MTCv3** to encrypt and decrypt data:

```typescript
import { MTCv3 } from 'mtcv3-encryption';

// Initialize with a password and salt
const password = 'strongpassword';
const salt = 'somesalt';
const mtc = new MTCv3(password, salt);

// Encrypt a message
const plaintext = 'HELLO WORLD';
const ciphertext = mtc.encrypt(plaintext);
console.log('Ciphertext:', ciphertext);

// Decrypt the message
const decryptedText = mtc.decrypt(ciphertext);
console.log('Decrypted Text:', decryptedText); // Output should be 'HELLO WORLD'
```

### **Custom Parameters**

The library allows customization for encryption rounds and matrix size. Adjust these parameters based on your security and performance requirements.

```typescript
const rounds = 12;
const matrixSize = 4; // Default size for AES-like encryption

const mtcCustom = new MTCv3(password, salt, rounds, matrixSize);

const customCiphertext = mtcCustom.encrypt(plaintext);
const customDecryptedText = mtcCustom.decrypt(customCiphertext);
console.log('Custom Decrypted Text:', customDecryptedText);
```

---

## **API Documentation**

### **Constructor**

```typescript
new MTCv3(password: string, salt: string, rounds?: number, matrixSize?: number)
```

- **`password`**: A string password used for key derivation.
- **`salt`**: A string salt for key derivation.
- **`rounds`** (optional): Number of encryption rounds. Default is `10`.
- **`matrixSize`** (optional): Size of the internal matrix. Default is `4`.

### **Methods**

- **`encrypt(plaintext: string): string`**: Encrypts the provided plaintext string and returns the ciphertext in hexadecimal format.

- **`decrypt(ciphertextHex: string): string`**: Decrypts the provided ciphertext (in hexadecimal format) and returns the plaintext string.

---

## **Security Considerations**

**Warning**: MTCv3 is a custom encryption algorithm and has not been formally peer-reviewed. While it incorporates AES-inspired components, it has not undergone extensive cryptanalysis. For critical or production-level applications, consider using standardized encryption methods like **AES** or **ChaCha20**.

**Padding Oracle Attack**: MTCv3 uses PKCS#7 padding in CBC mode. To prevent padding oracle attacks, ensure that padding errors do not leak information to the attacker.

---

## **Performance**

MTCv3 is optimized for flexibility rather than speed. It performs well in software-only environments but does not currently support hardware acceleration. For high-performance needs, AES with hardware acceleration or ChaCha20 may be more suitable.

---

## **Testing**

### **Unit Tests**

This project includes a suite of unit tests that verify encryption and decryption functionality, error handling, and consistency. To run the tests, you can use Jest or another testing framework:

```bash
yarn test
# or
npm test
```

### **Sample Tests**

```typescript
describe('MTCv3 Encryption', () => {
  it('should correctly encrypt and decrypt text', () => {
    const password = 'password';
    const salt = 'salt';
    const mtc = new MTCv3(password, salt);

    const plaintext = 'HELLO WORLD';
    const ciphertext = mtc.encrypt(plaintext);
    const decrypted = mtc.decrypt(ciphertext);

    expect(decrypted).toBe(plaintext);
  });
});
```

For more details on test coverage, refer to the `tests` directory.

---

## **License**

**MTCv3** is licensed under the MIT License. See `LICENSE` for more information.

---

This project is a work in progress, and contributions, suggestions, or discussions around improving security or performance are welcome.

---
