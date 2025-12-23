#pragma once

#include <string>

#include "srp/proto_codec.hpp"

namespace srp {

struct RangeProofVerification {
  bool ok{false};
  std::string message;
};

RangeProofVerification verifyRangeProof(const RangeProofWire& req);

}  // namespace srp

