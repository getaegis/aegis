import * as crypto from 'node:crypto';

/**
 * Shamir's Secret Sharing over GF(256).
 *
 * Splits a secret into N shares such that any K shares can reconstruct it,
 * but K−1 shares reveal nothing about the secret. Uses the finite field
 * GF(2^8) with the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1.
 */

// ─── GF(256) Arithmetic ───────────────────────────────────────────

/** Lookup tables for GF(256) multiplication via discrete logarithm. */
const EXP = new Uint8Array(256);
const LOG = new Uint8Array(256);

/**
 * Initialize exp/log tables using generator g = 0x03.
 * EXP[i] = g^i mod P(x) where P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).
 */
function initTables(): void {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    // Multiply by generator 3: x * 3 = x * 2 XOR x
    // x * 2 = left shift with conditional reduction by 0x1B
    const x2 = (x << 1) ^ (x & 0x80 ? 0x1b : 0);
    x = (x2 ^ x) & 0xff;
  }
  EXP[255] = EXP[0]; // Wrap for modular arithmetic convenience
}

initTables();

/** Addition in GF(256) — XOR. */
function gfAdd(a: number, b: number): number {
  return a ^ b;
}

/** Multiplication in GF(256) using log/exp tables. */
function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a] + LOG[b]) % 255];
}

/** Division in GF(256) using log/exp tables. */
function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('Division by zero in GF(256).');
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

// ─── Polynomial Evaluation ────────────────────────────────────────

/**
 * Evaluate a polynomial at point x in GF(256) using Horner's method.
 * coeffs[0] = constant term (the secret byte), coeffs[t−1] = leading term.
 */
function evalPoly(coeffs: number[], x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gfAdd(gfMul(result, x), coeffs[i]);
  }
  return result;
}

/** Generate a random non-zero byte using rejection sampling. */
function randomNonZero(): number {
  let b: number;
  do {
    b = crypto.randomBytes(1)[0];
  } while (b === 0);
  return b;
}

// ─── Public API ───────────────────────────────────────────────────

/** A single share from Shamir's Secret Sharing. */
export interface ShamirShare {
  /** Share index (1–255). Each share must have a unique index. */
  index: number;
  /** Share data — same length as the original secret. */
  data: Buffer;
}

/**
 * Split a secret into `totalShares` shares, requiring `threshold` to reconstruct.
 *
 * @param secret      The secret to split (arbitrary-length Buffer).
 * @param threshold   Minimum shares needed for reconstruction (2 ≤ t ≤ n).
 * @param totalShares Number of shares to produce (t ≤ n ≤ 255).
 * @returns Array of shares, each with a unique index and data.
 */
export function split(secret: Buffer, threshold: number, totalShares: number): ShamirShare[] {
  if (threshold < 2) throw new Error('Threshold must be at least 2.');
  if (totalShares < threshold) throw new Error('Total shares must be ≥ threshold.');
  if (totalShares > 255) throw new Error('Maximum 255 shares supported.');
  if (secret.length === 0) throw new Error('Secret must not be empty.');

  // Initialize empty shares
  const shares: ShamirShare[] = Array.from({ length: totalShares }, (_, i) => ({
    index: i + 1,
    data: Buffer.alloc(secret.length),
  }));

  // For each byte of the secret, create a random polynomial and evaluate at each share index
  for (let b = 0; b < secret.length; b++) {
    const coeffs = new Array<number>(threshold);
    coeffs[0] = secret[b]; // constant term = the secret byte

    // Random non-zero coefficients ensure polynomial has full degree
    for (let c = 1; c < threshold; c++) {
      coeffs[c] = randomNonZero();
    }

    for (let s = 0; s < totalShares; s++) {
      shares[s].data[b] = evalPoly(coeffs, shares[s].index);
    }
  }

  return shares;
}

/**
 * Reconstruct a secret from shares using Lagrange interpolation at x = 0.
 *
 * @param shares  At least `threshold` shares with unique indices.
 * @returns The reconstructed secret.
 */
export function combine(shares: ShamirShare[]): Buffer {
  if (shares.length < 2) throw new Error('At least 2 shares required.');

  const len = shares[0].data.length;
  if (!shares.every((s) => s.data.length === len)) {
    throw new Error('All shares must have the same data length.');
  }

  const indices = new Set(shares.map((s) => s.index));
  if (indices.size !== shares.length) {
    throw new Error('Duplicate share indices.');
  }

  const secret = Buffer.alloc(len);

  for (let b = 0; b < len; b++) {
    let value = 0;

    for (let i = 0; i < shares.length; i++) {
      const xi = shares[i].index;
      const yi = shares[i].data[b];

      // Lagrange basis polynomial L_i(0)
      let basis = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        const xj = shares[j].index;
        // L_i(0) = Π_{j≠i} (0 − x_j) / (x_i − x_j)
        // In GF(256): subtraction = addition = XOR, and 0 − x_j = x_j
        basis = gfMul(basis, gfDiv(xj, gfAdd(xi, xj)));
      }

      value = gfAdd(value, gfMul(yi, basis));
    }

    secret[b] = value;
  }

  return secret;
}

/**
 * Encode a share as a human-readable string.
 * Format: `aegis_share_<index_hex>_<data_hex>`
 */
export function encodeShare(share: ShamirShare): string {
  const idx = share.index.toString(16).padStart(2, '0');
  return `aegis_share_${idx}_${share.data.toString('hex')}`;
}

/**
 * Decode a share from its string representation.
 */
export function decodeShare(encoded: string): ShamirShare {
  const prefix = 'aegis_share_';
  if (!encoded.startsWith(prefix)) {
    throw new Error('Invalid share format: must start with "aegis_share_".');
  }

  const rest = encoded.slice(prefix.length);
  const sep = rest.indexOf('_');
  if (sep === -1) {
    throw new Error('Invalid share format: missing data separator.');
  }

  const index = Number.parseInt(rest.slice(0, sep), 16);
  if (Number.isNaN(index) || index < 1 || index > 255) {
    throw new Error('Invalid share index: must be 1–255.');
  }

  const data = Buffer.from(rest.slice(sep + 1), 'hex');
  if (data.length === 0) {
    throw new Error('Invalid share: empty data.');
  }

  return { index, data };
}
