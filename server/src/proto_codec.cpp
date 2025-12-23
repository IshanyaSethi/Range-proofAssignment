#include "srp/proto_codec.hpp"

#include <cstdio>
#include <cstring>

namespace srp {
namespace {

struct BytesView {
  const uint8_t* data{nullptr};
  size_t size{0};
};

bool encodeBytes(pb_ostream_t* stream, const pb_field_t* field, void* const* arg) {
  const auto* view = static_cast<const BytesView*>(*arg);
  if (!view) return false;
  if (!pb_encode_tag_for_field(stream, field)) return false;
  return pb_encode_string(stream, view->data, view->size);
}

bool decodeBytesToVector(pb_istream_t* stream, const pb_field_t*, void** arg) {
  auto* out = static_cast<ByteVec*>(*arg);
  if (!out) return false;
  const size_t n = stream->bytes_left;
  out->assign(n, 0);
  return pb_read(stream, out->data(), n);
}

struct PointListSink {
  std::vector<std::array<uint8_t, 33>>* out{nullptr};
};

bool decodePointToList(pb_istream_t* stream, const pb_field_t*, void** arg) {
  auto* sink = static_cast<PointListSink*>(*arg);
  if (!sink || !sink->out) return false;
  const size_t n = stream->bytes_left;
  if (n != 33) return false;
  if (sink->out->size() >= 4) return false;
  std::array<uint8_t, 33> p{};
  if (!pb_read(stream, p.data(), 33)) return false;
  sink->out->push_back(p);
  return true;
}

bool decodePointFixed33(pb_istream_t* stream, const pb_field_t*, void** arg) {
  auto* out = static_cast<std::array<uint8_t, 33>*>(*arg);
  if (!out) return false;
  const size_t n = stream->bytes_left;
  if (n != 33) return false;
  return pb_read(stream, out->data(), 33);
}

}  // namespace

bool decodeEnvelope(const ByteVec& in, DecodedEnvelope& out, std::string& err) {
  secure_range_proof_Envelope env = secure_range_proof_Envelope_init_zero;
  pb_istream_t is = pb_istream_from_buffer(in.data(), in.size());
  if (!pb_decode(&is, secure_range_proof_Envelope_fields, &env)) {
    err = PB_GET_ERROR(&is);
    return false;
  }
  out.type = env.type;
  out.has_request_id = env.has_request_id;
  out.request_id = env.request_id;
  out.payload.assign(env.payload.bytes, env.payload.bytes + env.payload.size);
  return true;
}

bool encodeEnvelope(secure_range_proof_MessageType type, const ByteVec& payload, ByteVec& out,
                    std::optional<uint32_t> request_id, std::string& err) {
  if (payload.size() > 2048) {
    err = "payload too large";
    return false;
  }
  secure_range_proof_Envelope env = secure_range_proof_Envelope_init_zero;
  env.type = type;
  env.payload.size = static_cast<pb_size_t>(payload.size());
  std::memcpy(env.payload.bytes, payload.data(), payload.size());
  if (request_id) {
    env.has_request_id = true;
    env.request_id = *request_id;
  }

  out.assign(secure_range_proof_Envelope_size, 0);
  pb_ostream_t os = pb_ostream_from_buffer(out.data(), out.size());
  if (!pb_encode(&os, secure_range_proof_Envelope_fields, &env)) {
    err = PB_GET_ERROR(&os);
    return false;
  }
  out.resize(os.bytes_written);
  return true;
}

bool decodeClientHello(const ByteVec& in, ClientHelloWire& out, std::string& err) {
  secure_range_proof_ClientHello msg = secure_range_proof_ClientHello_init_zero;
  ByteVec sig;
  msg.sig.funcs.decode = &decodeBytesToVector;
  msg.sig.arg = &sig;

  pb_istream_t is = pb_istream_from_buffer(in.data(), in.size());
  if (!pb_decode(&is, secure_range_proof_ClientHello_fields, &msg)) {
    err = PB_GET_ERROR(&is);
    return false;
  }
  out.serial_id.assign(reinterpret_cast<const char*>(msg.serial_id.bytes),
                       reinterpret_cast<const char*>(msg.serial_id.bytes) + msg.serial_id.size);
  out.sig64 = std::move(sig);
  return true;
}

bool encodeServerChallenge(const ServerChallengeWire& in, ByteVec& out, std::string& err) {
  secure_range_proof_ServerChallenge msg = secure_range_proof_ServerChallenge_init_zero;
  BytesView nonce{in.nonce32.data(), in.nonce32.size()};
  BytesView sig{in.sig64.data(), in.sig64.size()};

  msg.nonce.funcs.encode = &encodeBytes;
  msg.nonce.arg = &nonce;
  msg.server_sig.funcs.encode = &encodeBytes;
  msg.server_sig.arg = &sig;

  out.assign(secure_range_proof_ServerChallenge_size, 0);
  pb_ostream_t os = pb_ostream_from_buffer(out.data(), out.size());
  if (!pb_encode(&os, secure_range_proof_ServerChallenge_fields, &msg)) {
    err = PB_GET_ERROR(&os);
    return false;
  }
  out.resize(os.bytes_written);
  return true;
}

bool decodeClientResponse(const ByteVec& in, ClientResponseWire& out, std::string& err) {
  secure_range_proof_ClientResponse msg = secure_range_proof_ClientResponse_init_zero;
  ByteVec sig;
  msg.sig.funcs.decode = &decodeBytesToVector;
  msg.sig.arg = &sig;

  pb_istream_t is = pb_istream_from_buffer(in.data(), in.size());
  if (!pb_decode(&is, secure_range_proof_ClientResponse_fields, &msg)) {
    err = PB_GET_ERROR(&is);
    return false;
  }
  out.sig64 = std::move(sig);
  return true;
}

bool encodeAuthResult(bool ok, std::string_view message, ByteVec& out, std::string& err) {
  secure_range_proof_AuthResult msg = secure_range_proof_AuthResult_init_zero;
  msg.ok = ok;
  if (!message.empty()) {
    msg.has_message = true;
    std::snprintf(msg.message, sizeof(msg.message), "%.*s", static_cast<int>(message.size()),
                  message.data());
  }

  out.assign(secure_range_proof_AuthResult_size, 0);
  pb_ostream_t os = pb_ostream_from_buffer(out.data(), out.size());
  if (!pb_encode(&os, secure_range_proof_AuthResult_fields, &msg)) {
    err = PB_GET_ERROR(&os);
    return false;
  }
  out.resize(os.bytes_written);
  return true;
}

bool decodeRangeProofRequest(const ByteVec& in, RangeProofWire& out, std::string& err) {
  secure_range_proof_RangeProofRequest msg = secure_range_proof_RangeProofRequest_init_zero;
  out.lower_commit.clear();
  out.upper_commit.clear();

  msg.c1.funcs.decode = &decodePointFixed33;
  msg.c1.arg = &out.c1;
  msg.c2.funcs.decode = &decodePointFixed33;
  msg.c2.arg = &out.c2;

  PointListSink lower{&out.lower_commit};
  PointListSink upper{&out.upper_commit};
  msg.lower_commit.funcs.decode = &decodePointToList;
  msg.lower_commit.arg = &lower;
  msg.upper_commit.funcs.decode = &decodePointToList;
  msg.upper_commit.arg = &upper;

  pb_istream_t is = pb_istream_from_buffer(in.data(), in.size());
  if (!pb_decode(&is, secure_range_proof_RangeProofRequest_fields, &msg)) {
    err = PB_GET_ERROR(&is);
    return false;
  }
  out.min = msg.min;
  out.max = msg.max;
  out.bitlen = msg.bitlen;
  return true;
}

bool encodeRangeProofResult(bool ok, std::string_view message, ByteVec& out, std::string& err) {
  secure_range_proof_RangeProofResult msg = secure_range_proof_RangeProofResult_init_zero;
  msg.ok = ok;
  if (!message.empty()) {
    msg.has_message = true;
    std::snprintf(msg.message, sizeof(msg.message), "%.*s", static_cast<int>(message.size()),
                  message.data());
  }
  out.assign(secure_range_proof_RangeProofResult_size, 0);
  pb_ostream_t os = pb_ostream_from_buffer(out.data(), out.size());
  if (!pb_encode(&os, secure_range_proof_RangeProofResult_fields, &msg)) {
    err = PB_GET_ERROR(&os);
    return false;
  }
  out.resize(os.bytes_written);
  return true;
}

}  // namespace srp

