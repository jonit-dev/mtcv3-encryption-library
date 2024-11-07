import crypto from 'crypto';

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

// GF(2^8) multiplication function
function gfMul(a: number, b: number): number {
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
export function mixMatrix(matrix: number[][]): number[][] {
  const N = matrix.length;
  const result: number[][] = Array.from({ length: N }, () => Array(N).fill(0));

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
export function inverseMixMatrix(matrix: number[][]): number[][] {
  const N = matrix.length;
  const result: number[][] = Array.from({ length: N }, () => Array(N).fill(0));

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
export function permuteBits(
  data: number[],
  key: Buffer,
  round: number
): number[] {
  const shift = key[round % key.length] % 8;
  return data.map((byte) => ((byte << shift) | (byte >> (8 - shift))) & 0xff);
}

// Function to perform inverse bit-level permutation within each byte
export function inversePermuteBits(
  data: number[],
  key: Buffer,
  round: number
): number[] {
  const shift = key[round % key.length] % 8;
  return data.map((byte) => ((byte >> shift) | (byte << (8 - shift))) & 0xff);
}

// Function to generate column permutation based on key and round
export function generateColumnPermutation(
  key: Buffer,
  round: number,
  N: number
): number[] {
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
  const inverse = Array(permutation.length);
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
export function unpad(data: Buffer, blockSize: number): Buffer {
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
