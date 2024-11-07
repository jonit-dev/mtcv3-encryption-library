"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MTCv3 = void 0;
const crypto_1 = __importDefault(require("crypto"));
const encryptionConstants_1 = require("./constants/encryptionConstants");
const encryptionUtils_1 = require("./helpers/encryptionUtils");
class MTCv3 {
    constructor(password, salt, rounds = 10, matrixSize = 4) {
        this.rounds = rounds;
        this.matrixSize = matrixSize;
        // Derive key schedule
        const keyMaterial = (0, encryptionUtils_1.deriveKey)(password, salt, 100000, this.rounds * this.matrixSize);
        this.keySchedule = [];
        for (let r = 0; r < this.rounds; r++) {
            const start = r * this.matrixSize;
            const end = start + this.matrixSize;
            this.keySchedule.push(keyMaterial.slice(start, end));
        }
        // Initialize IV (for CBC mode)
        this.iv = crypto_1.default.randomBytes(this.matrixSize * this.matrixSize);
    }
    // Encryption Function
    encrypt(plaintext) {
        let data = Buffer.from(plaintext, 'utf-8');
        // Pad data
        const blockSize = this.matrixSize * this.matrixSize;
        data = (0, encryptionUtils_1.pad)(data, blockSize);
        // Divide into blocks
        const blocks = [];
        for (let i = 0; i < data.length; i += blockSize) {
            blocks.push(data.slice(i, i + blockSize));
        }
        // Encrypt each block using CBC mode
        const ciphertextBlocks = [];
        let previousCipher = this.iv;
        for (const block of blocks) {
            // XOR with previous cipher (CBC)
            const xored = Buffer.alloc(block.length);
            for (let i = 0; i < block.length; i++) {
                xored[i] = block[i] ^ previousCipher[i];
            }
            // Encrypt block
            const encrypted = this.encryptBlock(xored);
            // Update previous cipher
            previousCipher = encrypted;
            ciphertextBlocks.push(encrypted);
        }
        // Concatenate all ciphertext blocks with IV
        const finalBuffer = Buffer.concat([this.iv, ...ciphertextBlocks]);
        return finalBuffer.toString('hex');
    }
    // Decryption Function
    decrypt(ciphertextHex) {
        const ciphertextWithIV = Buffer.from(ciphertextHex, 'hex');
        const blockSize = this.matrixSize * this.matrixSize;
        if (ciphertextWithIV.length < blockSize) {
            throw new Error('Invalid ciphertext length');
        }
        const iv = ciphertextWithIV.slice(0, blockSize);
        const ciphertext = ciphertextWithIV.slice(blockSize);
        if (ciphertext.length % blockSize !== 0) {
            throw new Error('Invalid ciphertext length');
        }
        const blocks = [];
        for (let i = 0; i < ciphertext.length; i += blockSize) {
            blocks.push(ciphertext.slice(i, i + blockSize));
        }
        const plaintextBlocks = [];
        let previousCipher = iv;
        for (const block of blocks) {
            const decrypted = this.decryptBlock(block);
            const xored = Buffer.alloc(decrypted.length);
            for (let i = 0; i < decrypted.length; i++) {
                xored[i] = decrypted[i] ^ previousCipher[i];
            }
            plaintextBlocks.push(xored);
            previousCipher = block;
        }
        const plaintext = Buffer.concat(plaintextBlocks);
        try {
            const unpadded = (0, encryptionUtils_1.unpad)(plaintext, blockSize);
            return unpadded.toString('utf-8');
        }
        catch (error) {
            throw new Error('Decryption failed: Invalid padding');
        }
    }
    // Encrypt a single block
    encryptBlock(block) {
        let data = Array.from(block);
        for (let r = 0; r < this.rounds; r++) {
            const key = this.keySchedule[r];
            const shiftAmounts = Array.from(key);
            const matrix = this.fillMatrix(data, 'row');
            // Row Shifting
            const shiftedMatrix = (0, encryptionUtils_1.shiftRows)(matrix, shiftAmounts);
            // Column Permutation
            const permutation = (0, encryptionUtils_1.generateColumnPermutation)(key, r, this.matrixSize);
            const permutedMatrix = (0, encryptionUtils_1.permuteColumns)(shiftedMatrix, permutation);
            // S-Box Substitution
            let flatData = permutedMatrix.flat();
            flatData = (0, encryptionUtils_1.substituteBytes)(flatData, encryptionConstants_1.AES_S_BOX);
            // Mixing Layer
            const mixedMatrix = (0, encryptionUtils_1.mixMatrix)(this.reshape(flatData, this.matrixSize));
            // Bit-level Permutation
            flatData = mixedMatrix.flat();
            flatData = (0, encryptionUtils_1.permuteBits)(flatData, key, r);
            data = flatData;
        }
        return Buffer.from(data);
    }
    // Decrypt a single block
    decryptBlock(block) {
        let data = Array.from(block);
        for (let r = this.rounds - 1; r >= 0; r--) {
            const key = this.keySchedule[r];
            const shiftAmounts = Array.from(key);
            // Inverse Bit-level Permutation
            data = (0, encryptionUtils_1.inversePermuteBits)(data, key, r);
            let matrix = this.fillMatrix(data, 'row');
            // Inverse Mixing Layer
            matrix = (0, encryptionUtils_1.inverseMixMatrix)(matrix);
            // Inverse S-Box Substitution
            let flatData = matrix.flat();
            flatData = (0, encryptionUtils_1.inverseSubstituteBytes)(flatData, encryptionConstants_1.AES_INV_S_BOX);
            // Convert flat data back to matrix
            matrix = this.reshape(flatData, this.matrixSize);
            // Inverse Column Permutation
            const permutation = (0, encryptionUtils_1.generateColumnPermutation)(key, r, this.matrixSize);
            const inversePermutation = (0, encryptionUtils_1.generateInverseColumnPermutation)(permutation);
            matrix = (0, encryptionUtils_1.permuteColumns)(matrix, inversePermutation);
            // Inverse Row Shifting
            matrix = (0, encryptionUtils_1.inverseShiftRows)(matrix, shiftAmounts);
            data = matrix.flat();
        }
        return Buffer.from(data);
    }
    // Helper function to fill matrix
    fillMatrix(data, order) {
        const N = this.matrixSize;
        const matrix = Array.from({ length: N }, () => Array(N).fill(0));
        for (let i = 0; i < data.length; i++) {
            const row = order === 'row' ? Math.floor(i / N) : i % N;
            const col = order === 'row' ? i % N : Math.floor(i / N);
            matrix[row][col] = data[i];
        }
        return matrix;
    }
    // Helper function to reshape flat data into matrix
    reshape(data, N) {
        const matrix = Array.from({ length: N }, () => Array(N).fill(0));
        for (let i = 0; i < data.length; i++) {
            const row = Math.floor(i / N);
            const col = i % N;
            matrix[row][col] = data[i];
        }
        return matrix;
    }
}
exports.MTCv3 = MTCv3;
