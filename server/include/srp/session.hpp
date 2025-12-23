#pragma once

#include <boost/asio.hpp>
#include <array>
#include <memory>
#include <string>
#include <unordered_map>

#include "srp/framing.hpp"
#include "srp/proto_codec.hpp"

namespace srp {

struct ServerKeys {
  std::array<uint8_t, 32> server_priv{};
  std::array<uint8_t, 33> server_pub{};
};

struct ClientRegistry {
  // serial_id -> compressed pubkey33
  std::unordered_map<std::string, std::array<uint8_t, 33>> clients;
};

class Session : public std::enable_shared_from_this<Session> {
 public:
  Session(boost::asio::ip::tcp::socket socket, ServerKeys keys, ClientRegistry registry);
  void start();

 private:
  enum class State { AwaitHello, AwaitResponse, Authed };

  void readNext();
  void handleFrame(ByteVec frame);

  void handleHello(const ByteVec& payload);
  void handleClientResponse(const ByteVec& payload);
  void handleRangeProof(const ByteVec& payload, std::optional<uint32_t> request_id);

  void sendEnvelope(secure_range_proof_MessageType type, const ByteVec& payload,
                    std::optional<uint32_t> request_id);

  boost::asio::ip::tcp::socket socket_;
  State state_{State::AwaitHello};
  ServerKeys keys_;
  ClientRegistry registry_;

  std::string authed_serial_;
  std::array<uint8_t, 33> client_pub_{};
  std::array<uint8_t, 32> nonce_{};
};

}  // namespace srp

