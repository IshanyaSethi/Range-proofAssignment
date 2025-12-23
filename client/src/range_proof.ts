import crypto from "node:crypto";

import {
  SECP256K1_N,
  hashToScalar,
  modN,
  randomScalarNonZero,
  scalarMulGCompressed,
} from "./crypto_utils";
import { fourSquares } from "./four_squares";

export type RangeProof = {
  min: number;
  max: number;
  bitlen: number;
  c1: Buffer;
  c2: Buffer;
  lowerCommit: Buffer[]; // 4
  upperCommit: Buffer[]; // 4
};

function randomScalar(): bigint {
  const b = crypto.randomBytes(32);
  return modN(BigInt("0x" + b.toString("hex")));
}

function sum(xs: bigint[]): bigint {
  return xs.reduce((a, b) => a + b, 0n);
}

export function buildRangeProof(min: number, max: number, bitlen: number, x: number): RangeProof {
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || !Number.isSafeInteger(x)) {
    throw new Error("min/max/x must be safe integers");
  }
  if (min < 0 || max < 0 || x < 0) throw new Error("min/max/x must be >= 0");
  if (min > max) throw new Error("min > max");
  if (x < min || x > max) throw new Error("x not in [min,max]");
  if (bitlen <= 0 || bitlen > 32) throw new Error("bitlen must be 1..32 (demo constraint)");

  const w = x - min; // (x-a)
  const t = max - x; // (b-x)

  const [s0, s1, s2, s3] = fourSquares(w);
  const [t0, t1, t2, t3] = fourSquares(t);

  const h = hashToScalar("H");
  if (h === 0n) throw new Error("hashToScalar(H) unexpectedly 0");

  for (;;) {
    const r = randomScalarNonZero();

    const rParts = [randomScalar(), randomScalar(), randomScalar()];
    rParts.push(modN(r - sum(rParts)));
    const uParts = [randomScalar(), randomScalar(), randomScalar()];
    uParts.push(modN(r - sum(uParts)));

    const lowerScalars = [
      modN(BigInt(s0 * s0) + rParts[0] * h),
      modN(BigInt(s1 * s1) + rParts[1] * h),
      modN(BigInt(s2 * s2) + rParts[2] * h),
      modN(BigInt(s3 * s3) + rParts[3] * h),
    ];
    const upperScalars = [
      modN(BigInt(t0 * t0) - uParts[0] * h),
      modN(BigInt(t1 * t1) - uParts[1] * h),
      modN(BigInt(t2 * t2) - uParts[2] * h),
      modN(BigInt(t3 * t3) - uParts[3] * h),
    ];

    const c2Scalar = modN(BigInt(w) + r * h);
    const c1Scalar = modN(BigInt(t) - r * h);

    const all = [c1Scalar, c2Scalar, ...lowerScalars, ...upperScalars];
    if (all.some((v) => v === 0n)) continue; // avoid infinity point in ECDH

    const lowerCommit = lowerScalars.map((k) => scalarMulGCompressed(k));
    const upperCommit = upperScalars.map((k) => scalarMulGCompressed(k));
    const c1 = scalarMulGCompressed(c1Scalar);
    const c2 = scalarMulGCompressed(c2Scalar);

    // Sanity: these should hold in the scalar domain because H = h·G:
    // sum(lower) == (w + r·h) mod n
    // sum(upper) == (t - r·h) mod n
    const sumLower = modN(sum(lowerScalars));
    const sumUpper = modN(sum(upperScalars));
    if (sumLower !== c2Scalar) continue;
    if (sumUpper !== c1Scalar) continue;

    return { min, max, bitlen, c1, c2, lowerCommit, upperCommit };
  }
}

