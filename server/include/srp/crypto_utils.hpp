#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" {
#include "bignum.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "sha2.h"
}

namespace srp {

constexpr size_t kSigLen = 64;
constexpr size_t kPrivLen = 32;
constexpr size_t kPub33Len = 33;
constexpr size_t kPoint33Len = 33;

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len);

bool ecdsaVerifyDigest33(const std::array<uint8_t, kPub33Len>& pubkey33,
                         const std::array<uint8_t, 32>& digest,
                         const std::array<uint8_t, kSigLen>& sig64);

std::array<uint8_t, kSigLen> ecdsaSignDigest(const std::array<uint8_t, kPrivLen>& privkey32,
                                             const std::array<uint8_t, 32>& digest);

std::array<uint8_t, kPub33Len> pubkey33FromPriv(const std::array<uint8_t, kPrivLen>& privkey32);

bignum256 hashToScalar(std::string_view domain);
bignum256 scalarFromU64(uint64_t v);

curve_point pointFromCompressed33(const std::array<uint8_t, kPoint33Len>& p33);
std::array<uint8_t, kPoint33Len> pointToCompressed33(const curve_point& p);

curve_point pointAdd(const curve_point& a, const curve_point& b);

curve_point scalarMulG(const bignum256& k);

}  // namespace srp

