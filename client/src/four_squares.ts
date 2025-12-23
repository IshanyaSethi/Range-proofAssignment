import crypto from "node:crypto";

export type FourSquares = [number, number, number, number];

function isqrt(n: number): number {
  return Math.floor(Math.sqrt(n));
}

export function fourSquares(n: number, maxAttempts = 20000): FourSquares {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("n must be a non-negative safe integer");
  if (n === 0) return [0, 0, 0, 0];

  const limit = isqrt(n);
  const squares = new Array<number>(limit + 1);
  const squareToRoot = new Map<number, number>();
  for (let i = 0; i <= limit; i++) {
    const s = i * i;
    squares[i] = s;
    squareToRoot.set(s, i);
  }

  function twoSquares(m: number): [number, number] | null {
    const lim = isqrt(m);
    for (let a = 0; a <= lim; a++) {
      const r = m - a * a;
      const b = squareToRoot.get(r);
      if (b !== undefined) return [a, b];
    }
    return null;
  }

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const a = crypto.randomInt(0, limit + 1);
    const b = crypto.randomInt(0, limit + 1);
    const r1 = n - squares[a] - squares[b];
    if (r1 < 0) continue;
    const cd = twoSquares(r1);
    if (!cd) continue;
    return [a, b, cd[0], cd[1]];
  }

  // Deterministic fallback (slower but guaranteed for 32-bit-ish values).
  for (let a = 0; a <= limit; a++) {
    const r0 = n - squares[a];
    if (r0 < 0) continue;
    const limB = isqrt(r0);
    for (let b = 0; b <= limB; b++) {
      const r1 = r0 - b * b;
      if (r1 < 0) continue;
      const cd = twoSquares(r1);
      if (cd) return [a, b, cd[0], cd[1]];
    }
  }

  throw new Error("failed to find four-squares representation");
}

