#pragma once

#include <array>
#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace srp {

inline uint8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
  c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + (c - 'a'));
  throw std::invalid_argument("invalid hex");
}

inline std::vector<uint8_t> hexToBytes(std::string_view hex) {
  if ((hex.size() % 2) != 0) throw std::invalid_argument("hex length must be even");
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t hi = hexNibble(hex[i]);
    uint8_t lo = hexNibble(hex[i + 1]);
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

inline std::string bytesToHex(const uint8_t* data, size_t len) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = kHex[(data[i] >> 4) & 0xF];
    out[2 * i + 1] = kHex[data[i] & 0xF];
  }
  return out;
}

template <size_t N>
inline std::array<uint8_t, N> toFixed(const std::vector<uint8_t>& v) {
  if (v.size() != N) throw std::invalid_argument("wrong size");
  std::array<uint8_t, N> out{};
  std::copy(v.begin(), v.end(), out.begin());
  return out;
}

}  // namespace srp

