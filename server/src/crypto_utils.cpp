#include "srp/crypto_utils.hpp"

#include <cstring>
#include <stdexcept>

namespace srp {

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
  std::array<uint8_t, 32> out{};
  sha256_Raw(data, len, out.data());
  return out;
}

bool ecdsaVerifyDigest33(const std::array<uint8_t, kPub33Len>& pubkey33,
                         const std::array<uint8_t, 32>& digest,
                         const std::array<uint8_t, kSigLen>& sig64) {
  return ecdsa_verify_digest(&secp256k1, pubkey33.data(), sig64.data(), digest.data()) == 0;
}

std::array<uint8_t, kSigLen> ecdsaSignDigest(const std::array<uint8_t, kPrivLen>& privkey32,
                                             const std::array<uint8_t, 32>& digest) {
  std::array<uint8_t, kSigLen> sig{};
  if (ecdsa_sign_digest(&secp256k1, privkey32.data(), digest.data(), sig.data(), nullptr, nullptr) !=
      0) {
    throw std::runtime_error("ecdsa_sign_digest failed");
  }
  return sig;
}

std::array<uint8_t, kPub33Len> pubkey33FromPriv(const std::array<uint8_t, kPrivLen>& privkey32) {
  std::array<uint8_t, kPub33Len> out{};
  ecdsa_get_public_key33(&secp256k1, privkey32.data(), out.data());
  return out;
}

bignum256 hashToScalar(std::string_view domain) {
  auto digest = sha256(reinterpret_cast<const uint8_t*>(domain.data()), domain.size());
  bignum256 k{};
  bn_read_be(digest.data(), &k);
  bn_mod(&k, &secp256k1.order);
  return k;
}

bignum256 scalarFromU64(uint64_t v) {
  std::array<uint8_t, 32> buf{};
  for (int i = 0; i < 8; ++i) {
    buf[31 - i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
  }
  bignum256 k{};
  bn_read_be(buf.data(), &k);
  bn_mod(&k, &secp256k1.order);
  return k;
}

curve_point pointFromCompressed33(const std::array<uint8_t, kPoint33Len>& p33) {
  curve_point p{};
  if (!ecdsa_read_pubkey(&secp256k1, p33.data(), &p)) {
    throw std::runtime_error("invalid compressed point");
  }
  return p;
}

std::array<uint8_t, kPoint33Len> pointToCompressed33(const curve_point& p) {
  std::array<uint8_t, kPoint33Len> out{};
  compress_coords(&p, out.data());
  return out;
}

curve_point pointAdd(const curve_point& a, const curve_point& b) {
  curve_point out{};
  point_copy(&b, &out);
  point_add(&secp256k1, &a, &out);
  return out;
}

curve_point scalarMulG(const bignum256& k) {
  curve_point out{};
  scalar_multiply(&secp256k1, &k, &out);
  return out;
}

}  // namespace srp

