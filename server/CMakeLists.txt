cmake_minimum_required(VERSION 3.20)

project(secure_range_proof_server LANGUAGES C CXX)

find_package(Boost REQUIRED COMPONENTS system)

# ---- nanopb runtime ----
add_library(nanopb STATIC
  third_party/nanopb_src/pb_common.c
  third_party/nanopb_src/pb_decode.c
  third_party/nanopb_src/pb_encode.c
)
target_include_directories(nanopb PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanopb_src
)

# ---- trezor-crypto (minimal subset) ----
add_library(trezor_crypto STATIC
  third_party/trezor-crypto/address.c
  third_party/trezor-crypto/base58.c
  third_party/trezor-crypto/blake256.c
  third_party/trezor-crypto/blake2b.c
  third_party/trezor-crypto/blake2s.c
  third_party/trezor-crypto/bignum.c
  third_party/trezor-crypto/ecdsa.c
  third_party/trezor-crypto/hasher.c
  third_party/trezor-crypto/hmac_drbg.c
  third_party/trezor-crypto/hmac.c
  third_party/trezor-crypto/memzero.c
  third_party/trezor-crypto/rand.c
  third_party/trezor-crypto/rfc6979.c
  third_party/trezor-crypto/ripemd160.c
  third_party/trezor-crypto/secp256k1.c
  third_party/trezor-crypto/sha2.c
  third_party/trezor-crypto/sha3.c
  third_party/trezor-crypto/groestl.c
)
target_include_directories(trezor_crypto PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/trezor-crypto
)

# Provide strong RNG overrides for trezor-crypto weak RNG.
add_library(trezor_crypto_rng_override STATIC
  src/trezor_random_override.c
)
target_include_directories(trezor_crypto_rng_override PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/trezor-crypto
)
target_link_libraries(trezor_crypto_rng_override PUBLIC trezor_crypto)

# ---- generated protobuf (nanopb) ----
add_library(srpproto STATIC
  generated/secure_range_proof.pb.c
)
target_include_directories(srpproto PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/generated
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanopb_src
)
target_link_libraries(srpproto PUBLIC nanopb)

# ---- server app ----
add_executable(srp_server
  src/main.cpp
  src/framing.cpp
  src/proto_codec.cpp
  src/crypto_utils.cpp
  src/range_proof.cpp
  src/session.cpp
)
target_include_directories(srp_server PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(srp_server PRIVATE
  Boost::system
  srpproto
  nanopb
  trezor_crypto_rng_override
)

