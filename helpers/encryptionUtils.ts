import crypto from 'crypto';

// ------------------------------
// Helper Functions
// ------------------------------

// Function to perform PBKDF2 key derivation
export function deriveKey(
  password: string,
  salt: string,
  iterations: number,
  keyLength: number
): Buffer {
  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
}

// Function to apply S-box substitution
export function substituteBytes(data: number[], sBox: number[]): number[] {
  return data.map((byte) => sBox[byte]);
}

// Function to perform inverse S-box substitution
export function inverseSubstituteBytes(
  data: number[],
  invSBox: number[]
): number[] {
  return data.map((byte) => invSBox[byte]);
}

// Function to shift rows
export function shiftRows(
  matrix: number[][],
  shiftAmounts: number[]
): number[][] {
  return matrix.map((row, i) => {
    const shift = shiftAmounts[i] % row.length;
    return row.slice(-shift).concat(row.slice(0, -shift));
  });
}

// Function to inverse shift rows
export function inverseShiftRows(
  matrix: number[][],
  shiftAmounts: number[]
): number[][] {
  return matrix.map((row, i) => {
    const shift = shiftAmounts[i] % row.length;
    return row.slice(shift).concat(row.slice(0, shift));
  });
}

// Function to permute columns
export function permuteColumns(
  matrix: number[][],
  permutation: number[]
): number[][] {
  return matrix.map((row) => permutation.map((colIndex) => row[colIndex]));
}

// Function to inverse permute columns
export function inversePermuteColumns(
  matrix: number[][],
  permutation: number[]
): number[][] {
  const inversePermutation = permutation.slice();
  for (let i = 0; i < permutation.length; i++) {
    inversePermutation[permutation[i]] = i;
  }
  return matrix.map((row) =>
    inversePermutation.map((colIndex) => row[colIndex])
  );
}

// Function to perform mixing layer (matrix multiplication modulo 256)
export function mixMatrix(
  matrix: number[][],
  mixingMatrix: number[][]
): number[][] {
  const N = matrix.length;
  const result: number[][] = Array.from({ length: N }, () => Array(N).fill(0));

  for (let i = 0; i < N; i++) {
    // Rows of mixingMatrix
    for (let j = 0; j < N; j++) {
      // Columns of matrix
      let sum = 0;
      for (let k = 0; k < N; k++) {
        sum += mixingMatrix[i][k] * matrix[k][j];
      }
      result[i][j] = sum % 256;
    }
  }

  return result;
}

// Function to perform inverse mixing layer
export function inverseMixMatrix(
  matrix: number[][],
  inverseMixingMatrix: number[][]
): number[][] {
  const N = matrix.length;
  const result: number[][] = Array.from({ length: N }, () => Array(N).fill(0));

  for (let i = 0; i < N; i++) {
    // Rows of inverseMixingMatrix
    for (let j = 0; j < N; j++) {
      // Columns of matrix
      let sum = 0;
      for (let k = 0; k < N; k++) {
        sum += inverseMixingMatrix[i][k] * matrix[k][j];
      }
      result[i][j] = sum % 256;
    }
  }

  return result;
}

// Function to perform bit-level permutation within each byte
export function permuteBits(
  data: number[],
  key: Buffer,
  round: number
): number[] {
  // Example: Rotate bits left by (key[round % key.length] % 8)
  const shift = key[round % key.length] % 8;
  return data.map((byte) => ((byte << shift) | (byte >> (8 - shift))) & 0xff);
}

// Function to perform inverse bit-level permutation within each byte
export function inversePermuteBits(
  data: number[],
  key: Buffer,
  round: number
): number[] {
  // Reverse the permutation: rotate bits right by (key[round % key.length] % 8)
  const shift = key[round % key.length] % 8;
  return data.map((byte) => ((byte >> shift) | (byte << (8 - shift))) & 0xff);
}

// Function to generate column permutation based on key and round
export function generateColumnPermutation(
  key: Buffer,
  round: number,
  N: number
): number[] {
  // Use a pseudo-random approach based on key and round
  const hash = crypto
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
export function generateInverseColumnPermutation(
  permutation: number[]
): number[] {
  const inverse = Array(permutation.length).fill(0);
  permutation.forEach((p, i) => {
    inverse[p] = i;
  });
  return inverse;
}

// Function to pad plaintext (PKCS#7)
export function pad(data: Buffer, blockSize: number): Buffer {
  const padding = blockSize - (data.length % blockSize);
  const paddingBuffer = Buffer.alloc(padding, padding);
  return Buffer.concat([data, paddingBuffer]);
}

// Function to unpad plaintext (PKCS#7)
export function unpad(data: Buffer): Buffer {
  const padding = data[data.length - 1];

  // Ensure padding value is within valid range
  if (padding === 0 || padding > data.length) {
    throw new Error('Invalid padding value');
  }

  // Check if all padding bytes have the correct value
  const paddingStart = data.length - padding;
  for (let i = data.length - 1; i >= paddingStart; i--) {
    if (data[i] !== padding) {
      throw new Error('Inconsistent padding bytes');
    }
  }

  return data.slice(0, data.length - padding);
}
