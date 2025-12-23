import crypto from "node:crypto";

export const SECP256K1_N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

function mod(a: bigint, n: bigint): bigint {
  const r = a % n;
  return r >= 0n ? r : r + n;
}

export function sha256(data: Buffer): Buffer {
  return crypto.createHash("sha256").update(data).digest();
}

export function randomScalarNonZero(): bigint {
  for (;;) {
    const b = crypto.randomBytes(32);
    const x = mod(BigInt("0x" + b.toString("hex")), SECP256K1_N);
    if (x !== 0n) return x;
  }
}

export function bigintTo32BE(x: bigint): Buffer {
  const v = x.toString(16).padStart(64, "0");
  return Buffer.from(v, "hex");
}

export function scalarMulGCompressed(s: bigint): Buffer {
  if (s === 0n) throw new Error("scalar is zero");
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(bigintTo32BE(mod(s, SECP256K1_N)));
  return ecdh.getPublicKey(undefined, "compressed");
}

export function compressedToUncompressed(pub33Hex: string): Buffer {
  const uncompressedHex = crypto.ECDH.convertKey(
    pub33Hex,
    "secp256k1",
    "hex",
    "hex",
    "uncompressed"
  ) as string;
  return Buffer.from(uncompressedHex, "hex");
}

// ---- Minimal ASN.1 DER builders (enough for EC keys) ----

function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let x = n;
  while (x > 0) {
    bytes.unshift(x & 0xff);
    x >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTL(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(value.length), value]);
}

function derSeq(children: Buffer[]): Buffer {
  return derTL(0x30, Buffer.concat(children));
}

function derInt(n: number): Buffer {
  if (n < 0 || n > 0x7fffffff) throw new Error("int out of range");
  return derTL(0x02, Buffer.from([n]));
}

function derOctetString(b: Buffer): Buffer {
  return derTL(0x04, b);
}

function derBitString(b: Buffer): Buffer {
  // prepend "unused bits" = 0
  return derTL(0x03, Buffer.concat([Buffer.from([0x00]), b]));
}

function derOid(arcs: number[]): Buffer {
  if (arcs.length < 2) throw new Error("oid too short");
  const out: number[] = [];
  out.push(arcs[0] * 40 + arcs[1]);
  for (const arc of arcs.slice(2)) {
    if (arc < 0) throw new Error("invalid oid arc");
    const tmp: number[] = [];
    let v = arc >>> 0;
    tmp.unshift(v & 0x7f);
    v >>= 7;
    while (v > 0) {
      tmp.unshift(0x80 | (v & 0x7f));
      v >>= 7;
    }
    out.push(...tmp);
  }
  return derTL(0x06, Buffer.from(out));
}

function derExplicit(tagNo: number, inner: Buffer): Buffer {
  // [tagNo] EXPLICIT (constructed)
  return derTL(0xa0 + tagNo, inner);
}

const OID_EC_PUBLIC_KEY = [1, 2, 840, 10045, 2, 1];
const OID_SECP256K1 = [1, 3, 132, 0, 10];

export function makeEcPrivateKeyObject(priv32: Buffer): crypto.KeyObject {
  if (priv32.length !== 32) throw new Error("priv32 must be 32 bytes");
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(priv32);
  const pubUncompressed = ecdh.getPublicKey(undefined, "uncompressed");

  // RFC5915 ECPrivateKey
  const der = derSeq([
    derInt(1),
    derOctetString(priv32),
    derExplicit(0, derOid(OID_SECP256K1)),
    derExplicit(1, derBitString(pubUncompressed)),
  ]);

  return crypto.createPrivateKey({ key: der, format: "der", type: "sec1" });
}

export function makeEcPublicKeyObjectFromCompressed(pub33Hex: string): crypto.KeyObject {
  const pubUncompressed = compressedToUncompressed(pub33Hex);
  const alg = derSeq([derOid(OID_EC_PUBLIC_KEY), derOid(OID_SECP256K1)]);
  const spki = derSeq([alg, derBitString(pubUncompressed)]);
  return crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
}

export function signP1363Sha256(priv: crypto.KeyObject, msg: Buffer): Buffer {
  return crypto.sign("sha256", msg, { key: priv, dsaEncoding: "ieee-p1363" });
}

export function verifyP1363Sha256(pub: crypto.KeyObject, msg: Buffer, sig64: Buffer): boolean {
  return crypto.verify("sha256", msg, { key: pub, dsaEncoding: "ieee-p1363" }, sig64);
}

export function hashToScalar(domain: string): bigint {
  const h = sha256(Buffer.from(domain, "utf8"));
  return mod(BigInt("0x" + h.toString("hex")), SECP256K1_N);
}

export function modN(x: bigint): bigint {
  return mod(x, SECP256K1_N);
}

