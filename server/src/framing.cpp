#include "srp/framing.hpp"

#include <array>

namespace srp {
namespace {

inline uint32_t readU32BE(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void writeU32BE(uint32_t v, uint8_t* p) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[3] = static_cast<uint8_t>(v & 0xFF);
}

}  // namespace

void asyncReadFrame(boost::asio::ip::tcp::socket& socket,
                    std::function<void(const boost::system::error_code&, ByteVec)> cb) {
  auto header = std::make_shared<std::array<uint8_t, 4>>();
  boost::asio::async_read(
      socket, boost::asio::buffer(*header),
      [header, &socket, cb = std::move(cb)](const boost::system::error_code& ec,
                                           std::size_t) mutable {
        if (ec) return cb(ec, {});
        uint32_t len = readU32BE(header->data());
        if (len == 0 || len > (1024u * 1024u)) {
          return cb(make_error_code(boost::system::errc::message_size), {});
        }
        auto body = std::make_shared<ByteVec>(len);
        boost::asio::async_read(
            socket, boost::asio::buffer(*body),
            [body, cb = std::move(cb)](const boost::system::error_code& ec2,
                                       std::size_t) mutable { cb(ec2, ec2 ? ByteVec{} : *body); });
      });
}

void asyncWriteFrame(boost::asio::ip::tcp::socket& socket, ByteVec payload,
                     std::function<void(const boost::system::error_code&)> cb) {
  auto header = std::make_shared<std::array<uint8_t, 4>>();
  writeU32BE(static_cast<uint32_t>(payload.size()), header->data());
  auto out = std::make_shared<ByteVec>();
  out->reserve(4 + payload.size());
  out->insert(out->end(), header->begin(), header->end());
  out->insert(out->end(), payload.begin(), payload.end());
  boost::asio::async_write(socket, boost::asio::buffer(*out),
                           [out, cb = std::move(cb)](const boost::system::error_code& ec,
                                                    std::size_t) mutable { cb(ec); });
}

}  // namespace srp

