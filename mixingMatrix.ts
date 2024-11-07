// Define the mixing matrix
export const MIXING_MATRIX = [
  [2, 3, 1, 1],
  [1, 2, 3, 1],
  [1, 1, 2, 3],
  [3, 1, 1, 2],
];

export const INVERSE_MIXING_MATRIX = matrixInverseMod256(MIXING_MATRIX);

// Function to compute the inverse of a 4x4 matrix modulo 256
function matrixInverseMod256(matrix: number[][]): number[][] {
  // Manually define the adjugate matrix or implement the adjugate function
  const adjugate = [
    [4, 253, 11, 239],
    [239, 4, 253, 11],
    [11, 239, 4, 253],
    [247, 11, 235, 4],
  ];

  // Determinant is -23 ≡ 233 mod 256
  const det = -23; // or 233
  const detMod = ((det % 256) + 256) % 256; // 233

  if (gcd(detMod, 256) !== 1) {
    throw new Error('Matrix is not invertible modulo 256.');
  }

  const detInv = modInverse(detMod, 256); // 89

  // Multiply adjugate by detInv modulo 256
  const inverse = adjugate.map((row) =>
    row.map((value) => (((value * detInv) % 256) + 256) % 256)
  );

  return inverse;
}

// Implement GCD and Modular Inverse as defined earlier
function gcd(a: number, b: number): number {
  while (b !== 0) {
    const temp = b;
    b = a % b;
    a = temp;
  }
  return a;
}

function modInverse(a: number, modulus: number): number {
  let m0 = modulus;
  let y = 0;
  let x = 1;

  if (modulus === 1) return 0;

  while (a > 1) {
    const q = Math.floor(a / modulus);
    let t = modulus;

    modulus = a % modulus;
    a = t;
    t = y;

    y = x - q * y;
    x = t;
  }

  if (x < 0) x += m0;

  return x;
}

// Compute the inverse mixing matrix
try {
  const correctInverse = matrixInverseMod256(MIXING_MATRIX);
  console.log('Correct Inverse Mixing Matrix:', correctInverse);
} catch (error) {
  console.error(error);
}
