"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
exports.substituteBytes = substituteBytes;
exports.inverseSubstituteBytes = inverseSubstituteBytes;
exports.shiftRows = shiftRows;
exports.inverseShiftRows = inverseShiftRows;
exports.permuteColumns = permuteColumns;
exports.mixMatrix = mixMatrix;
exports.inverseMixMatrix = inverseMixMatrix;
exports.permuteBits = permuteBits;
exports.inversePermuteBits = inversePermuteBits;
exports.generateColumnPermutation = generateColumnPermutation;
exports.generateInverseColumnPermutation = generateInverseColumnPermutation;
exports.pad = pad;
exports.unpad = unpad;
const crypto_1 = __importDefault(require("crypto"));
// Function to perform PBKDF2 key derivation
function deriveKey(password, salt, iterations, keyLength) {
    return crypto_1.default.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
}
// Function to apply S-box substitution
function substituteBytes(data, sBox) {
    return data.map((byte) => sBox[byte]);
}
// Function to perform inverse S-box substitution
function inverseSubstituteBytes(data, invSBox) {
    return data.map((byte) => invSBox[byte]);
}
// Function to shift rows
function shiftRows(matrix, shiftAmounts) {
    return matrix.map((row, i) => {
        const shift = shiftAmounts[i] % row.length;
        return row.slice(-shift).concat(row.slice(0, -shift));
    });
}
// Function to inverse shift rows
function inverseShiftRows(matrix, shiftAmounts) {
    return matrix.map((row, i) => {
        const shift = shiftAmounts[i] % row.length;
        return row.slice(shift).concat(row.slice(0, shift));
    });
}
// Function to permute columns
function permuteColumns(matrix, permutation) {
    return matrix.map((row) => permutation.map((colIndex) => row[colIndex]));
}
// GF(2^8) multiplication function
function gfMul(a, b) {
    let p = 0;
    for (let counter = 0; counter < 8; counter++) {
        if (b & 1) {
            p ^= a;
        }
        const hiBitSet = a & 0x80;
        a = (a << 1) & 0xff;
        if (hiBitSet) {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    return p;
}
// Function to perform mixing layer (AES MixColumns)
function mixMatrix(matrix) {
    const N = matrix.length;
    const result = Array.from({ length: N }, () => Array(N).fill(0));
    for (let c = 0; c < N; c++) {
        const a = matrix.map((row) => row[c]);
        result[0][c] = gfMul(a[0], 2) ^ gfMul(a[1], 3) ^ a[2] ^ a[3];
        result[1][c] = a[0] ^ gfMul(a[1], 2) ^ gfMul(a[2], 3) ^ a[3];
        result[2][c] = a[0] ^ a[1] ^ gfMul(a[2], 2) ^ gfMul(a[3], 3);
        result[3][c] = gfMul(a[0], 3) ^ a[1] ^ a[2] ^ gfMul(a[3], 2);
    }
    return result;
}
// Function to perform inverse mixing layer (AES InvMixColumns)
function inverseMixMatrix(matrix) {
    const N = matrix.length;
    const result = Array.from({ length: N }, () => Array(N).fill(0));
    for (let c = 0; c < N; c++) {
        const a = matrix.map((row) => row[c]);
        result[0][c] =
            gfMul(a[0], 14) ^ gfMul(a[1], 11) ^ gfMul(a[2], 13) ^ gfMul(a[3], 9);
        result[1][c] =
            gfMul(a[0], 9) ^ gfMul(a[1], 14) ^ gfMul(a[2], 11) ^ gfMul(a[3], 13);
        result[2][c] =
            gfMul(a[0], 13) ^ gfMul(a[1], 9) ^ gfMul(a[2], 14) ^ gfMul(a[3], 11);
        result[3][c] =
            gfMul(a[0], 11) ^ gfMul(a[1], 13) ^ gfMul(a[2], 9) ^ gfMul(a[3], 14);
    }
    return result;
}
// Function to perform bit-level permutation within each byte
function permuteBits(data, key, round) {
    const shift = key[round % key.length] % 8;
    return data.map((byte) => ((byte << shift) | (byte >> (8 - shift))) & 0xff);
}
// Function to perform inverse bit-level permutation within each byte
function inversePermuteBits(data, key, round) {
    const shift = key[round % key.length] % 8;
    return data.map((byte) => ((byte >> shift) | (byte << (8 - shift))) & 0xff);
}
// Function to generate column permutation based on key and round
function generateColumnPermutation(key, round, N) {
    const hash = crypto_1.default
        .createHash('sha256')
        .update(key)
        .update(Buffer.from([round]))
        .digest();
    const permutation = Array.from({ length: N }, (_, i) => i);
    for (let i = permutation.length - 1; i > 0; i--) {
        const j = hash[i % hash.length] % (i + 1);
        [permutation[i], permutation[j]] = [permutation[j], permutation[i]];
    }
    return permutation;
}
// Function to generate inverse column permutation
function generateInverseColumnPermutation(permutation) {
    const inverse = Array(permutation.length);
    permutation.forEach((p, i) => {
        inverse[p] = i;
    });
    return inverse;
}
// Function to pad plaintext (PKCS#7)
function pad(data, blockSize) {
    const padding = blockSize - (data.length % blockSize);
    const paddingBuffer = Buffer.alloc(padding, padding);
    return Buffer.concat([data, paddingBuffer]);
}
// Function to unpad plaintext (PKCS#7)
function unpad(data, blockSize) {
    if (data.length === 0) {
        throw new Error('Empty data buffer');
    }
    const lastByte = data[data.length - 1];
    if (lastByte === 0 || lastByte > data.length || lastByte > blockSize) {
        throw new Error('Invalid padding value');
    }
    for (let i = data.length - lastByte; i < data.length; i++) {
        if (data[i] !== lastByte) {
            throw new Error('Invalid padding pattern');
        }
    }
    return data.slice(0, data.length - lastByte);
}
