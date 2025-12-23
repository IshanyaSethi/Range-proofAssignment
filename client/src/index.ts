import net from "node:net";
import crypto from "node:crypto";

import { loadClientConfig } from "./config";
import { FrameDecoder, encodeFrame } from "./framing";
import { decodeMessage, encodeMessage, loadProto } from "./proto";
import {
  makeEcPrivateKeyObject,
  makeEcPublicKeyObjectFromCompressed,
  signP1363Sha256,
  verifyP1363Sha256,
} from "./crypto_utils";
import { buildRangeProof } from "./range_proof";

type Envelope = {
  type: number;
  payload: Buffer;
  requestId?: number;
};

function parseArgs(argv: string[]) {
  const out: Record<string, string> = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const k = a.slice(2);
    const v = argv[i + 1];
    if (!v || v.startsWith("--")) {
      out[k] = "true";
    } else {
      out[k] = v;
      i++;
    }
  }
  return out;
}

class ProtoChannel {
  private decoder = new FrameDecoder();
  private queue: Buffer[] = [];
  private waiters: ((b: Buffer) => void)[] = [];

  constructor(private socket: net.Socket) {
    socket.on("data", (chunk) => {
      const frames = this.decoder.push(chunk);
      for (const f of frames) this.pushFrame(f);
    });
    socket.on("close", () => {
      while (this.waiters.length) this.waiters.shift()!(Buffer.alloc(0));
    });
  }

  private pushFrame(f: Buffer) {
    const w = this.waiters.shift();
    if (w) w(f);
    else this.queue.push(f);
  }

  async recvFrame(): Promise<Buffer> {
    if (this.queue.length) return this.queue.shift()!;
    return await new Promise((resolve) => this.waiters.push(resolve));
  }

  sendFrame(payload: Buffer) {
    this.socket.write(encodeFrame(payload));
  }
}

async function main() {
  const args = parseArgs(process.argv);
  const host = args.host ?? "127.0.0.1";
  const port = Number(args.port ?? "9000");
  const configPath = args.config ?? `${__dirname}/../config/client.conf`;

  const bitlen = Number(args.bitlen ?? "32");
  const min = Number(args.min ?? "0");
  const max =
    args.max !== undefined ? Number(args.max) : Math.pow(2, bitlen) - 1;
  const requests = Number(args.requests ?? "1");

  const cfg = loadClientConfig(configPath);
  const proto = await loadProto();

  const clientPriv = makeEcPrivateKeyObject(Buffer.from(cfg.clientPrivKeyHex, "hex"));
  const serverPub = makeEcPublicKeyObjectFromCompressed(cfg.serverPubKeyHex);

  const socket = net.createConnection({ host, port });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", (e) => reject(e));
  });
  const ch = new ProtoChannel(socket);

  const serialBuf = Buffer.from(cfg.clientSerialId, "utf8");

  // ---- Auth step 1: ClientHello ----
  const helloSig = signP1363Sha256(clientPriv, serialBuf);
  const helloPayload = encodeMessage(proto.ClientHello, {
    serialId: serialBuf,
    sig: helloSig,
  });
  const helloEnv = encodeMessage(proto.Envelope, {
    type: proto.MessageType.values.MSG_CLIENT_HELLO,
    payload: helloPayload,
  });
  ch.sendFrame(helloEnv);

  // ---- Auth step 2: ServerChallenge ----
  const challFrame = await ch.recvFrame();
  const challEnv = decodeMessage<Envelope>(proto.Envelope, challFrame);
  if (challEnv.type !== proto.MessageType.values.MSG_SERVER_CHALLENGE) {
    throw new Error(`expected server challenge, got type=${challEnv.type}`);
  }
  const chall = decodeMessage<{ nonce: Buffer; serverSig: Buffer }>(
    proto.ServerChallenge,
    challEnv.payload
  );

  const toVerify = Buffer.concat([serialBuf, Buffer.from(chall.nonce)]);
  if (!verifyP1363Sha256(serverPub, toVerify, Buffer.from(chall.serverSig))) {
    throw new Error("server signature verification failed");
  }

  // ---- Auth step 3: ClientResponse ----
  const respSig = signP1363Sha256(clientPriv, Buffer.from(chall.nonce));
  const respPayload = encodeMessage(proto.ClientResponse, { sig: respSig });
  const respEnv = encodeMessage(proto.Envelope, {
    type: proto.MessageType.values.MSG_CLIENT_RESPONSE,
    payload: respPayload,
  });
  ch.sendFrame(respEnv);

  const authFrame = await ch.recvFrame();
  const authEnv = decodeMessage<Envelope>(proto.Envelope, authFrame);
  if (authEnv.type !== proto.MessageType.values.MSG_AUTH_RESULT) {
    throw new Error(`expected auth result, got type=${authEnv.type}`);
  }
  const auth = decodeMessage<{ ok: boolean; message?: string }>(
    proto.AuthResult,
    authEnv.payload
  );
  if (!auth.ok) throw new Error(`auth failed: ${auth.message ?? ""}`);
  console.log(`[auth] ok: ${auth.message ?? ""}`);

  // ---- Range proofs ----
  for (let i = 0; i < requests; i++) {
    const x = crypto.randomInt(min, max + 1);
    const proof = buildRangeProof(min, max, bitlen, x);

    const reqPayload = encodeMessage(proto.RangeProofRequest, {
      min: proof.min,
      max: proof.max,
      bitlen: proof.bitlen,
      c1: proof.c1,
      c2: proof.c2,
      lowerCommit: proof.lowerCommit,
      upperCommit: proof.upperCommit,
    });
    const reqId = i + 1;
    const reqEnv = encodeMessage(proto.Envelope, {
      type: proto.MessageType.values.MSG_RANGE_PROOF_REQUEST,
      payload: reqPayload,
      requestId: reqId,
    });
    ch.sendFrame(reqEnv);

    const resFrame = await ch.recvFrame();
    const resEnv = decodeMessage<Envelope>(proto.Envelope, resFrame);
    if (resEnv.type !== proto.MessageType.values.MSG_RANGE_PROOF_RESULT) {
      throw new Error(`expected range proof result, got type=${resEnv.type}`);
    }
    if (resEnv.requestId !== undefined && resEnv.requestId !== reqId) {
      throw new Error(`mismatched request_id: expected ${reqId}, got ${resEnv.requestId}`);
    }
    const res = decodeMessage<{ ok: boolean; message?: string }>(
      proto.RangeProofResult,
      resEnv.payload
    );
    console.log(
      `[range-proof] ${res.ok ? "OK" : "FAIL"}: ${res.message ?? ""} (min=${min}, max=${max}, bitlen=${bitlen})`
    );
  }

  socket.end();
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

