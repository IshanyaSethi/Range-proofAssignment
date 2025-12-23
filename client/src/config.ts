import fs from "node:fs";

export type ClientConfig = {
  clientSerialId: string;
  clientPrivKeyHex: string;
  serverPubKeyHex: string;
};

function trim(s: string): string {
  return s.trim();
}

export function loadClientConfig(path: string): ClientConfig {
  const raw = fs.readFileSync(path, "utf8");
  const kv = new Map<string, string>();
  for (const line0 of raw.split(/\r?\n/)) {
    const line = trim(line0);
    if (!line || line.startsWith("#")) continue;
    const idx = line.indexOf("=");
    if (idx < 0) continue;
    kv.set(trim(line.slice(0, idx)), trim(line.slice(idx + 1)));
  }

  const clientSerialId = kv.get("client_serial_id") ?? "";
  const clientPrivKeyHex = kv.get("client_privkey_hex") ?? "";
  const serverPubKeyHex = kv.get("server_pubkey_hex") ?? "";
  if (!clientSerialId || !clientPrivKeyHex || !serverPubKeyHex) {
    throw new Error("missing required client config keys");
  }
  return { clientSerialId, clientPrivKeyHex, serverPubKeyHex };
}

