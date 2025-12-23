#include "srp/session.hpp"

#include <iostream>

extern "C" {
#include "rand.h"
}

#include "srp/crypto_utils.hpp"
#include "srp/range_proof.hpp"

namespace srp {

Session::Session(boost::asio::ip::tcp::socket socket, ServerKeys keys, ClientRegistry registry)
    : socket_(std::move(socket)), keys_(keys), registry_(std::move(registry)) {}

void Session::start() { readNext(); }

void Session::readNext() {
  auto self = shared_from_this();
  asyncReadFrame(socket_, [self](const boost::system::error_code& ec, ByteVec frame) {
    if (ec) {
      // Socket closed or error.
      return;
    }
    self->handleFrame(std::move(frame));
  });
}

void Session::handleFrame(ByteVec frame) {
  DecodedEnvelope env;
  std::string err;
  if (!decodeEnvelope(frame, env, err)) {
    socket_.close();
    return;
  }

  switch (env.type) {
    case secure_range_proof_MessageType_MSG_CLIENT_HELLO:
      handleHello(env.payload);
      break;
    case secure_range_proof_MessageType_MSG_CLIENT_RESPONSE:
      handleClientResponse(env.payload);
      break;
    case secure_range_proof_MessageType_MSG_RANGE_PROOF_REQUEST:
      handleRangeProof(env.payload, env.has_request_id ? std::optional<uint32_t>(env.request_id)
                                                       : std::nullopt);
      break;
    default:
      socket_.close();
      return;
  }

  readNext();
}

void Session::handleHello(const ByteVec& payload) {
  if (state_ != State::AwaitHello) {
    socket_.close();
    return;
  }

  ClientHelloWire hello;
  std::string err;
  if (!decodeClientHello(payload, hello, err)) {
    socket_.close();
    return;
  }
  if (hello.sig64.size() != kSigLen) {
    socket_.close();
    return;
  }

  auto it = registry_.clients.find(hello.serial_id);
  if (it == registry_.clients.end()) {
    std::cerr << "unknown client serial: " << hello.serial_id << "\n";
    socket_.close();
    return;
  }
  client_pub_ = it->second;

  std::array<uint8_t, kSigLen> sig{};
  std::copy(hello.sig64.begin(), hello.sig64.end(), sig.begin());

  const auto digest =
      sha256(reinterpret_cast<const uint8_t*>(hello.serial_id.data()), hello.serial_id.size());

  if (!ecdsaVerifyDigest33(client_pub_, digest, sig)) {
    std::cerr << "client hello signature verification failed for serial=" << hello.serial_id
              << "\n";
    socket_.close();
    return;
  }

  authed_serial_ = hello.serial_id;
  random_buffer(nonce_.data(), nonce_.size());

  // Server signs sha256(serial||nonce) so client can bind challenge to serial.
  ByteVec sn;
  sn.reserve(authed_serial_.size() + nonce_.size());
  sn.insert(sn.end(), authed_serial_.begin(), authed_serial_.end());
  sn.insert(sn.end(), nonce_.begin(), nonce_.end());
  const auto chall_digest = sha256(sn.data(), sn.size());
  const auto server_sig = ecdsaSignDigest(keys_.server_priv, chall_digest);

  ServerChallengeWire chall;
  chall.nonce32.assign(nonce_.begin(), nonce_.end());
  chall.sig64.assign(server_sig.begin(), server_sig.end());

  ByteVec challPayload;
  if (!encodeServerChallenge(chall, challPayload, err)) {
    socket_.close();
    return;
  }

  sendEnvelope(secure_range_proof_MessageType_MSG_SERVER_CHALLENGE, challPayload, std::nullopt);
  state_ = State::AwaitResponse;
}

void Session::handleClientResponse(const ByteVec& payload) {
  if (state_ != State::AwaitResponse) {
    socket_.close();
    return;
  }

  ClientResponseWire resp;
  std::string err;
  if (!decodeClientResponse(payload, resp, err)) {
    socket_.close();
    return;
  }
  if (resp.sig64.size() != kSigLen) {
    socket_.close();
    return;
  }
  std::array<uint8_t, kSigLen> sig{};
  std::copy(resp.sig64.begin(), resp.sig64.end(), sig.begin());

  const auto digest = sha256(nonce_.data(), nonce_.size());
  if (!ecdsaVerifyDigest33(client_pub_, digest, sig)) {
    std::cerr << "client response signature verification failed for serial=" << authed_serial_
              << "\n";
    ByteVec authPayload;
    encodeAuthResult(false, "auth failed", authPayload, err);
    sendEnvelope(secure_range_proof_MessageType_MSG_AUTH_RESULT, authPayload, std::nullopt);
    socket_.close();
    return;
  }

  std::cout << "Client verified: serial_id=" << authed_serial_ << "\n";
  ByteVec authPayload;
  encodeAuthResult(true, "auth ok", authPayload, err);
  sendEnvelope(secure_range_proof_MessageType_MSG_AUTH_RESULT, authPayload, std::nullopt);
  state_ = State::Authed;
}

void Session::handleRangeProof(const ByteVec& payload, std::optional<uint32_t> request_id) {
  if (state_ != State::Authed) {
    socket_.close();
    return;
  }

  RangeProofWire req;
  std::string err;
  if (!decodeRangeProofRequest(payload, req, err)) {
    socket_.close();
    return;
  }

  auto res = verifyRangeProof(req);
  std::cout << (res.ok ? "[range-proof] OK: " : "[range-proof] FAIL: ") << res.message << "\n";

  ByteVec outPayload;
  encodeRangeProofResult(res.ok, res.message, outPayload, err);
  sendEnvelope(secure_range_proof_MessageType_MSG_RANGE_PROOF_RESULT, outPayload, request_id);
}

void Session::sendEnvelope(secure_range_proof_MessageType type, const ByteVec& payload,
                           std::optional<uint32_t> request_id) {
  ByteVec env;
  std::string err;
  if (!encodeEnvelope(type, payload, env, request_id, err)) {
    socket_.close();
    return;
  }
  auto self = shared_from_this();
  asyncWriteFrame(socket_, std::move(env), [self](const boost::system::error_code& ec) {
    if (ec) {
      self->socket_.close();
    }
  });
}

}  // namespace srp

