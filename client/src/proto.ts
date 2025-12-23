import path from "node:path";
import protobuf from "protobufjs";

export type Proto = {
  root: protobuf.Root;
  MessageType: protobuf.Enum;
  Envelope: protobuf.Type;
  ClientHello: protobuf.Type;
  ServerChallenge: protobuf.Type;
  ClientResponse: protobuf.Type;
  AuthResult: protobuf.Type;
  RangeProofRequest: protobuf.Type;
  RangeProofResult: protobuf.Type;
};

export async function loadProto(): Promise<Proto> {
  const protoPath = path.join(__dirname, "../../proto/secure_range_proof.proto");
  const root = await protobuf.load(protoPath);
  const MessageType = root.lookupEnum("secure_range_proof.MessageType");
  const Envelope = root.lookupType("secure_range_proof.Envelope");
  const ClientHello = root.lookupType("secure_range_proof.ClientHello");
  const ServerChallenge = root.lookupType("secure_range_proof.ServerChallenge");
  const ClientResponse = root.lookupType("secure_range_proof.ClientResponse");
  const AuthResult = root.lookupType("secure_range_proof.AuthResult");
  const RangeProofRequest = root.lookupType("secure_range_proof.RangeProofRequest");
  const RangeProofResult = root.lookupType("secure_range_proof.RangeProofResult");

  return {
    root,
    MessageType,
    Envelope,
    ClientHello,
    ServerChallenge,
    ClientResponse,
    AuthResult,
    RangeProofRequest,
    RangeProofResult,
  };
}

export function encodeMessage(type: protobuf.Type, obj: Record<string, any>): Buffer {
  const err = type.verify(obj);
  if (err) throw new Error(err);
  const msg = type.create(obj);
  return Buffer.from(type.encode(msg).finish());
}

export function decodeMessage<T>(type: protobuf.Type, buf: Buffer): T {
  return type.decode(buf) as unknown as T;
}

