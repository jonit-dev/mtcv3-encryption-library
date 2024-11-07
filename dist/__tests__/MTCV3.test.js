"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const MTCV3_1 = require("../MTCV3");
const encryptionUtils_1 = require("../helpers/encryptionUtils");
// Importing performance hooks from Node.js for high-resolution timing
describe('MTCv3', () => {
    const password = 'strongpassword';
    const salt = 'somesalt';
    let mtc;
    beforeEach(() => {
        mtc = new MTCV3_1.MTCv3(password, salt);
    });
    describe('encryption and decryption', () => {
        it('should correctly encrypt and decrypt text', () => {
            const plaintext = 'HELLO WORLD';
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        it('should handle empty string', () => {
            const plaintext = '';
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        it('should handle long text', () => {
            const plaintext = 'A'.repeat(1000);
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        it('should handle special characters', () => {
            const plaintext = '!@#$%^&*()_+-=[]{}|;:,.<>?`~';
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        it('should handle unicode characters', () => {
            const plaintext = '你好世界😀🌍';
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        it('should handle single character', () => {
            const plaintext = 'A';
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        it('should handle exact block size', () => {
            const blockSize = 16; // matrixSize = 4, so blockSize = 4 * 4 = 16
            const plaintext = 'A'.repeat(blockSize); // 16 characters
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
    });
    describe('error handling', () => {
        it('should throw error when decrypting invalid ciphertext', () => {
            expect(() => {
                mtc.decrypt('invalid-hex-string');
            }).toThrow();
        });
        it('should throw error when decrypting truncated ciphertext', () => {
            const ciphertext = mtc.encrypt('test');
            const truncated = ciphertext.substring(0, ciphertext.length - 2);
            expect(() => {
                mtc.decrypt(truncated);
            }).toThrow('Invalid ciphertext length');
        });
        it('should throw error when ciphertext is empty', () => {
            expect(() => {
                mtc.decrypt('');
            }).toThrow('Invalid ciphertext length');
        });
    });
    describe('initialization', () => {
        it('should accept custom rounds parameter', () => {
            const customRounds = 12;
            const mtcCustom = new MTCV3_1.MTCv3(password, salt, customRounds);
            const plaintext = 'test';
            const ciphertext = mtcCustom.encrypt(plaintext);
            const decrypted = mtcCustom.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        // Removed the 'different matrix sizes' test as MTCv3 is designed for matrixSize=4
        it('should default to matrix size 4 when not specified', () => {
            const plaintext = 'test message';
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
    });
    describe('different instances', () => {
        it('should not decrypt text encrypted with different password', () => {
            const plaintext = 'test';
            const ciphertext = mtc.encrypt(plaintext);
            const mtc2 = new MTCV3_1.MTCv3('differentpassword', salt);
            expect(() => {
                mtc2.decrypt(ciphertext);
            }).toThrow('Decryption failed: Invalid padding');
        });
        it('should not decrypt text encrypted with different salt', () => {
            const plaintext = 'test';
            const ciphertext = mtc.encrypt(plaintext);
            const mtc2 = new MTCV3_1.MTCv3(password, 'differentsalt');
            expect(() => {
                mtc2.decrypt(ciphertext);
            }).toThrow('Decryption failed: Invalid padding');
        });
    });
    describe('mixing functions', () => {
        it('should correctly mix and inverse mix a 4x4 matrix', () => {
            const inputMatrix = [
                [1, 2, 3, 4],
                [5, 6, 7, 8],
                [9, 10, 11, 12],
                [13, 14, 15, 16],
            ];
            const mixedMatrix = (0, encryptionUtils_1.mixMatrix)(inputMatrix);
            const inverseMixedMatrix = (0, encryptionUtils_1.inverseMixMatrix)(mixedMatrix);
            expect(inverseMixedMatrix).toEqual(inputMatrix);
        });
        it('should correctly pad and unpad data', () => {
            const data = Buffer.from('Hello World');
            const blockSize = 16; // matrixSize = 4
            const paddedData = (0, encryptionUtils_1.pad)(data, blockSize);
            const unpaddedData = (0, encryptionUtils_1.unpad)(paddedData, blockSize);
            expect(unpaddedData.toString()).toBe(data.toString());
        });
        it('should throw error when unpadding invalid padding', () => {
            const invalidPaddedData = Buffer.from('Hello World\x05\x05\x05\x05');
            const blockSize = 16;
            expect(() => {
                (0, encryptionUtils_1.unpad)(invalidPaddedData, blockSize);
            }).toThrow('Invalid padding pattern');
        });
        it('should pad data to the next block size', () => {
            const data = Buffer.from('1234567890ABCDEF'); // 16 bytes
            const blockSize = 16;
            const paddedData = (0, encryptionUtils_1.pad)(data, blockSize);
            expect(paddedData.length).toBe(32); // Next multiple of blockSize
            expect(paddedData.slice(16)).toEqual(Buffer.alloc(16, 16)); // PKCS#7 padding
        });
    });
    // Removed the 'performance comparison' test as it's not suitable for unit tests
    describe('edge cases', () => {
        it('should handle plaintext that is a multiple of block size without altering data', () => {
            const blockSize = 16;
            const plaintext = 'A'.repeat(blockSize); // 16 characters
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        it('should handle plaintext that requires padding', () => {
            const blockSize = 16;
            const plaintext = 'A'.repeat(blockSize - 5); // 11 characters
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(plaintext);
        });
        it('should handle plaintext with all possible byte values', () => {
            const allBytes = Buffer.from([...Array(256).keys()]);
            const plaintext = allBytes.toString('latin1'); // Using 'latin1' to preserve byte values
            const ciphertext = mtc.encrypt(plaintext);
            const decrypted = mtc.decrypt(ciphertext);
            expect(decrypted).toBe(allBytes.toString('latin1'));
        });
    });
});
