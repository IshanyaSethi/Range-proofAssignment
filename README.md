## Secure Range Proof System (Client–Server)

This repository implements a **TCP client–server system** that performs:

- **Mutual authentication** using **ECDSA (secp256k1)** and **SHA-256**
- A **range proof protocol** following the **ECC commitment structure** described in the prompt
- **Protobuf encoding** end-to-end:
  - **Server**: C++ + **nanopb**
  - **Client**: Node.js + TypeScript + **protobufjs**

### Repository structure

- **`proto/`**: Shared `.proto` schema (`secure_range_proof.proto`)
- **`server/`**: C++ server (Boost.Asio + trezor-crypto + nanopb)
- **`client/`**: Node.js TypeScript client (net + crypto + protobufjs)

---

## Protocol summary

### Authentication

- **Client → Server**: `ClientHello`
  - `serial_id`
  - `sig = ECDSA_sign( SHA256(serial_id) )`
- **Server → Client**: `ServerChallenge`
  - `nonce` (32 random bytes)
  - `server_sig = ECDSA_sign( SHA256(serial_id || nonce) )`
- **Client → Server**: `ClientResponse`
  - `sig = ECDSA_sign( SHA256(nonce) )`
- **Server** prints: `Client verified: serial_id=<serial>`

All signatures are **P1363 / IEEE** format (`r||s`, **64 bytes**).

### Range proof (ECC commitments)

Client proves a secret \(x\) lies in \([a,b]\) by proving both:

- \(x-a \ge 0\)
- \(b-x \ge 0\)

Using the “sum of four squares” fact and ECC commitments:

- Lower commitment: `c2 = (x-a)·G + r·H`
- Upper commitment: `c1 = (b-x)·G − r·H`
- Plus **4 sub-commitments** each for `(x-a)` and `(b-x)` using the squares decomposition

Server verifies:

- `sum(lower_commit[i]) == c2`
- `sum(upper_commit[i]) == c1`
- `c1 + c2 == (b-a)·G`
- `p1 = b·G − c1` equals `p2 = c2 + a·G`

> Note: this follows the prompt’s structure. It is a **demonstration** of the described protocol and is **not a production-grade ZK range proof**.

---

## Build & run (macOS)

### Prerequisites

Install tools via Homebrew:

```bash
brew update
brew install cmake boost protobuf python node
python3 -m pip install --user protobuf
```

### Build server (C++)

From repo root:

```bash
cmake -S . -B build
cmake --build build -j
./build/server/srp_server --port 9000 --config server/config/server.conf
```

### Run client (Node.js / TypeScript)

In a second terminal:

```bash
cd client
npm install
npm run dev -- --host 127.0.0.1 --port 9000 --config ./config/client.conf --bitlen 16 --requests 1
```

You should see:

- client: `[auth] ok: ...`
- server: `Client verified: serial_id=...`
- both sides: range-proof verification success

---

## Build & run (Linux)

### Prerequisites (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libboost-system-dev protobuf-compiler python3-pip nodejs npm
python3 -m pip install --user protobuf
```

### Build/run

Same as macOS.

---

## Configuration

### Server config (`server/config/server.conf`)

- `server_privkey_hex=<32-byte-hex>`
- `client.<serial>.pubkey_hex=<33-byte-compressed-pubkey-hex>`

### Client config (`client/config/client.conf`)

- `client_serial_id=<serial>`
- `client_privkey_hex=<32-byte-hex>`
- `server_pubkey_hex=<33-byte-compressed-pubkey-hex>`

> The included configs use **demo keys**. Replace them for any real use.

---

## Regenerating nanopb sources (optional)

The server includes already-generated nanopb files in `server/generated/`.
If you change `proto/secure_range_proof.proto`, regenerate with:

```bash
bash ./server/tools/generate_proto.sh
```

---

## Create a submission zip (optional helper)

```bash
bash ./tools/make_zip.sh
```

