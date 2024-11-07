import crypto from 'crypto';
import {
  AES_INV_S_BOX,
  AES_S_BOX,
  INVERSE_MIXING_MATRIX,
  MIXING_MATRIX,
} from './constants/encryptionConstants';
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
  private mixingMatrix: number[][];
  private inverseMixingMatrix: number[][];
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

    // Define mixing matrix and its inverse
    this.mixingMatrix = MIXING_MATRIX;
    this.inverseMixingMatrix = INVERSE_MIXING_MATRIX;

    // Initialize IV (for CBC mode)
    this.iv = crypto.randomBytes(this.matrixSize * this.matrixSize);
  }

  // Encryption Function
  encrypt(plaintext: string): string {
    // Convert plaintext to Buffer
    let data = Buffer.from(plaintext, 'utf-8');
    console.log('Original data length:', data.length);

    // Pad data
    const blockSize = this.matrixSize * this.matrixSize;
    data = pad(data, blockSize);
    console.log('Padded data length:', data.length);

    // Divide into blocks
    const blocks: Buffer[] = [];
    for (let i = 0; i < data.length; i += blockSize) {
      blocks.push(data.slice(i, i + blockSize));
    }
    console.log('Number of blocks:', blocks.length);

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
      let encrypted = this.encryptBlock(xored);

      // Update previous cipher
      previousCipher = encrypted;

      ciphertextBlocks.push(encrypted);
    }

    // Concatenate all ciphertext blocks
    const ciphertext = Buffer.concat(ciphertextBlocks);
    console.log('Final ciphertext length:', ciphertext.length);

    // Prepend IV for decryption
    const finalBuffer = Buffer.concat([this.iv, ciphertext]);
    console.log('Final buffer length (with IV):', finalBuffer.length);
    return finalBuffer.toString('hex');
  }

  // Decryption Function
  decrypt(ciphertextHex: string): string {
    const ciphertextWithIV = Buffer.from(ciphertextHex, 'hex');
    console.log(
      'Received ciphertext length (with IV):',
      ciphertextWithIV.length
    );

    // Extract IV
    const blockSize = this.matrixSize * this.matrixSize;
    const iv = ciphertextWithIV.slice(0, blockSize);
    const ciphertext = ciphertextWithIV.slice(blockSize);
    console.log('Ciphertext length (without IV):', ciphertext.length);

    // Divide into blocks
    const blocks: Buffer[] = [];
    for (let i = 0; i < ciphertext.length; i += blockSize) {
      blocks.push(ciphertext.slice(i, i + blockSize));
    }
    console.log('Number of blocks to decrypt:', blocks.length);

    // Decrypt each block using CBC mode
    const plaintextBlocks: Buffer[] = [];
    let previousCipher: Buffer = iv;
    for (const block of blocks) {
      // Decrypt block
      let decrypted = this.decryptBlock(block);

      // XOR with previous cipher (CBC)
      const xored = Buffer.alloc(decrypted.length);
      for (let i = 0; i < decrypted.length; i++) {
        xored[i] = decrypted[i] ^ previousCipher[i];
      }

      // Update previous cipher
      previousCipher = block;

      plaintextBlocks.push(xored);
    }

    // Concatenate all plaintext blocks
    let plaintext = Buffer.concat(plaintextBlocks);
    console.log('Decrypted data length (before unpad):', plaintext.length);

    // Unpad data
    plaintext = unpad(plaintext);
    console.log('Final decrypted length:', plaintext.length);

    return plaintext.toString('utf-8');
  }

  // Encrypt a single block
  private encryptBlock(block: Buffer): Buffer {
    let data = Array.from(block);

    for (let r = 0; r < this.rounds; r++) {
      const key = this.keySchedule[r];
      const shiftAmounts = Array.from(key); // Using key bytes as shift amounts

      // Fill matrix in row-major order
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
      const mixedMatrix = mixMatrix(
        this.reshape(flatData, this.matrixSize),
        this.mixingMatrix
      );

      // Bit-level Permutation
      flatData = mixedMatrix.flat();
      flatData = permuteBits(flatData, key, r);

      // Prepare data for next round
      data = flatData;
    }

    // Return encrypted block
    return Buffer.from(data);
  }

  // Decrypt a single block
  private decryptBlock(block: Buffer): Buffer {
    let data = Array.from(block);

    for (let r = this.rounds - 1; r >= 0; r--) {
      const key = this.keySchedule[r];
      const shiftAmounts = Array.from(key); // Using key bytes as shift amounts

      // Bit-level Permutation Inversion
      data = inversePermuteBits(data, key, r);

      // **Corrected: Use 'row' instead of 'column'**
      let matrix = this.fillMatrix(data, 'row');

      // Inverse Mixing Layer
      matrix = inverseMixMatrix(matrix, this.inverseMixingMatrix);

      // Inverse S-Box Substitution
      let flatData = matrix.flat();
      flatData = inverseSubstituteBytes(flatData, AES_INV_S_BOX);

      // Convert flat data back to matrix
      matrix = this.reshape(flatData, this.matrixSize);

      // Inverse Column Permutation
      const permutation = generateColumnPermutation(
        this.keySchedule[r],
        r,
        this.matrixSize
      );
      const inversePermutation = generateInverseColumnPermutation(permutation);
      matrix = permuteColumns(matrix, inversePermutation);

      // Inverse Row Shifting
      matrix = inverseShiftRows(matrix, shiftAmounts);

      // Flatten matrix to data
      data = matrix.flat();
    }

    // Return decrypted block
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
