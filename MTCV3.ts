import crypto from 'crypto';
import { AES_INV_S_BOX, AES_S_BOX } from './constants/encryptionConstants';
import {
  deriveKey,
  generateColumnPermutation,
  generateInverseColumnPermutation,
  inverseMixMatrix,
  inversePermuteBits,
  inverseShiftRows,
  inverseSubstituteBytes,
  mixMatrix,
  pad,
  permuteBits,
  permuteColumns,
  shiftRows,
  substituteBytes,
  unpad,
} from './helpers/encryptionUtils';

export class MTCv3 {
  private keySchedule: Buffer[];
  private rounds: number;
  private matrixSize: number;
  private iv: Buffer;

  constructor(
    password: string,
    salt: string,
    rounds: number = 10,
    matrixSize: number = 4
  ) {
    this.rounds = rounds;
    this.matrixSize = matrixSize;

    // Derive key schedule
    const keyMaterial = deriveKey(
      password,
      salt,
      100000,
      this.rounds * this.matrixSize
    );
    this.keySchedule = [];
    for (let r = 0; r < this.rounds; r++) {
      const start = r * this.matrixSize;
      const end = start + this.matrixSize;
      this.keySchedule.push(keyMaterial.slice(start, end));
    }

    // Initialize IV (for CBC mode)
    this.iv = crypto.randomBytes(this.matrixSize * this.matrixSize);
  }

  // Encryption Function
  encrypt(plaintext: string): string {
    let data = Buffer.from(plaintext, 'utf-8');

    // Pad data
    const blockSize = this.matrixSize * this.matrixSize;
    data = pad(data, blockSize);

    // Divide into blocks
    const blocks: Buffer[] = [];
    for (let i = 0; i < data.length; i += blockSize) {
      blocks.push(data.slice(i, i + blockSize));
    }

    // Encrypt each block using CBC mode
    const ciphertextBlocks: Buffer[] = [];
    let previousCipher: Buffer = this.iv;

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
  decrypt(ciphertextHex: string): string {
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

    const blocks: Buffer[] = [];
    for (let i = 0; i < ciphertext.length; i += blockSize) {
      blocks.push(ciphertext.slice(i, i + blockSize));
    }

    const plaintextBlocks: Buffer[] = [];
    let previousCipher: Buffer = iv;

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
      const unpadded = unpad(plaintext, blockSize);
      return unpadded.toString('utf-8');
    } catch (error) {
      throw new Error('Decryption failed: Invalid padding');
    }
  }

  // Encrypt a single block
  private encryptBlock(block: Buffer): Buffer {
    let data = Array.from(block);

    for (let r = 0; r < this.rounds; r++) {
      const key = this.keySchedule[r];
      const shiftAmounts = Array.from(key);

      const matrix = this.fillMatrix(data, 'row');

      // Row Shifting
      const shiftedMatrix = shiftRows(matrix, shiftAmounts);

      // Column Permutation
      const permutation = generateColumnPermutation(key, r, this.matrixSize);
      const permutedMatrix = permuteColumns(shiftedMatrix, permutation);

      // S-Box Substitution
      let flatData = permutedMatrix.flat();
      flatData = substituteBytes(flatData, AES_S_BOX);

      // Mixing Layer
      const mixedMatrix = mixMatrix(this.reshape(flatData, this.matrixSize));

      // Bit-level Permutation
      flatData = mixedMatrix.flat();
      flatData = permuteBits(flatData, key, r);

      data = flatData;
    }

    return Buffer.from(data);
  }

  // Decrypt a single block
  private decryptBlock(block: Buffer): Buffer {
    let data = Array.from(block);

    for (let r = this.rounds - 1; r >= 0; r--) {
      const key = this.keySchedule[r];
      const shiftAmounts = Array.from(key);

      // Inverse Bit-level Permutation
      data = inversePermuteBits(data, key, r);

      let matrix = this.fillMatrix(data, 'row');

      // Inverse Mixing Layer
      matrix = inverseMixMatrix(matrix);

      // Inverse S-Box Substitution
      let flatData = matrix.flat();
      flatData = inverseSubstituteBytes(flatData, AES_INV_S_BOX);

      // Convert flat data back to matrix
      matrix = this.reshape(flatData, this.matrixSize);

      // Inverse Column Permutation
      const permutation = generateColumnPermutation(key, r, this.matrixSize);
      const inversePermutation = generateInverseColumnPermutation(permutation);
      matrix = permuteColumns(matrix, inversePermutation);

      // Inverse Row Shifting
      matrix = inverseShiftRows(matrix, shiftAmounts);

      data = matrix.flat();
    }

    return Buffer.from(data);
  }

  // Helper function to fill matrix
  private fillMatrix(data: number[], order: 'row' | 'column'): number[][] {
    const N = this.matrixSize;
    const matrix: number[][] = Array.from({ length: N }, () =>
      Array(N).fill(0)
    );

    for (let i = 0; i < data.length; i++) {
      const row = order === 'row' ? Math.floor(i / N) : i % N;
      const col = order === 'row' ? i % N : Math.floor(i / N);
      matrix[row][col] = data[i];
    }

    return matrix;
  }

  // Helper function to reshape flat data into matrix
  private reshape(data: number[], N: number): number[][] {
    const matrix: number[][] = Array.from({ length: N }, () =>
      Array(N).fill(0)
    );
    for (let i = 0; i < data.length; i++) {
      const row = Math.floor(i / N);
      const col = i % N;
      matrix[row][col] = data[i];
    }
    return matrix;
  }
}
