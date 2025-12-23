#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "srp/framing.hpp"

extern "C" {
#include <pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
}

#include "secure_range_proof.pb.h"

namespace srp {

struct DecodedEnvelope {
  secure_range_proof_MessageType type{};
  bool has_request_id{false};
  uint32_t request_id{0};
  ByteVec payload;
};

bool decodeEnvelope(const ByteVec& in, DecodedEnvelope& out, std::string& err);
bool encodeEnvelope(secure_range_proof_MessageType type, const ByteVec& payload, ByteVec& out,
                    std::optional<uint32_t> request_id, std::string& err);

struct ClientHelloWire {
  std::string serial_id;
  ByteVec sig64;  // 64 bytes r||s
};

struct ServerChallengeWire {
  ByteVec nonce32;
  ByteVec sig64;
};

struct ClientResponseWire {
  ByteVec sig64;
};

struct RangeProofWire {
  uint64_t min{0};
  uint64_t max{0};
  uint32_t bitlen{0};
  std::array<uint8_t, 33> c1{};
  std::array<uint8_t, 33> c2{};
  std::vector<std::array<uint8_t, 33>> lower_commit;  // size 4
  std::vector<std::array<uint8_t, 33>> upper_commit;  // size 4
};

bool decodeClientHello(const ByteVec& in, ClientHelloWire& out, std::string& err);
bool encodeServerChallenge(const ServerChallengeWire& in, ByteVec& out, std::string& err);
bool decodeClientResponse(const ByteVec& in, ClientResponseWire& out, std::string& err);
bool encodeAuthResult(bool ok, std::string_view message, ByteVec& out, std::string& err);

bool decodeRangeProofRequest(const ByteVec& in, RangeProofWire& out, std::string& err);
bool encodeRangeProofResult(bool ok, std::string_view message, ByteVec& out, std::string& err);

}  // namespace srp

