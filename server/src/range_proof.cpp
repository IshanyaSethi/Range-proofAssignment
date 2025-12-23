#include "srp/range_proof.hpp"

#include <sstream>

#include "srp/crypto_utils.hpp"

namespace srp {
namespace {

curve_point negatePoint(const curve_point& p) {
  curve_point out{};
  point_copy(&p, &out);
  // out.y = -y mod prime
  bn_subtractmod(&secp256k1.prime, &p.y, &out.y, &secp256k1.prime);
  return out;
}

}  // namespace

RangeProofVerification verifyRangeProof(const RangeProofWire& req) {
  if (req.min > req.max) return {false, "min > max"};
  if (req.bitlen == 0 || req.bitlen > 32) return {false, "bitlen must be 1..32 (demo constraint)"};

  // Demo guard: force range to fit in bitlen.
  const uint64_t maxAllowed =
      (req.bitlen == 64) ? UINT64_MAX : ((static_cast<uint64_t>(1) << req.bitlen) - 1);
  if (req.max > maxAllowed) return {false, "max exceeds 2^bitlen-1"};

  if (req.lower_commit.size() != 4 || req.upper_commit.size() != 4) {
    return {false, "expected exactly 4 lower_commit and 4 upper_commit points"};
  }

  curve_point c1 = pointFromCompressed33(req.c1);
  curve_point c2 = pointFromCompressed33(req.c2);

  curve_point sumLower{};
  point_set_infinity(&sumLower);
  for (const auto& p33 : req.lower_commit) {
    curve_point p = pointFromCompressed33(p33);
    point_add(&secp256k1, &p, &sumLower);
  }
  if (!point_is_equal(&sumLower, &c2)) {
    return {false, "lower_commit sum does not match c2"};
  }

  curve_point sumUpper{};
  point_set_infinity(&sumUpper);
  for (const auto& p33 : req.upper_commit) {
    curve_point p = pointFromCompressed33(p33);
    point_add(&secp256k1, &p, &sumUpper);
  }
  if (!point_is_equal(&sumUpper, &c1)) {
    return {false, "upper_commit sum does not match c1"};
  }

  // Check c1 + c2 == (b-a)·G  (r·H cancels)
  curve_point c1_plus_c2 = pointAdd(c1, c2);
  const uint64_t width = req.max - req.min;
  curve_point widthG = scalarMulG(scalarFromU64(width));
  if (!point_is_equal(&c1_plus_c2, &widthG)) {
    return {false, "c1 + c2 != (max-min)·G"};
  }

  // Verifier's ECC range check from prompt:
  // p1 = b·G − c1
  // p2 = c2 + a·G
  curve_point bG = scalarMulG(scalarFromU64(req.max));
  curve_point p1 = pointAdd(bG, negatePoint(c1));
  curve_point aG = scalarMulG(scalarFromU64(req.min));
  curve_point p2 = pointAdd(c2, aG);
  if (!point_is_equal(&p1, &p2)) {
    return {false, "p1 != p2"};
  }

  std::ostringstream oss;
  oss << "verified range proof for [min=" << req.min << ", max=" << req.max
      << "], bitlen=" << req.bitlen;
  return {true, oss.str()};
}

}  // namespace srp

