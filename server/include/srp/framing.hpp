#pragma once

#include <boost/asio.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace srp {

using ByteVec = std::vector<uint8_t>;

// Frames messages as:
//   uint32_be length
//   <length bytes payload>
void asyncReadFrame(boost::asio::ip::tcp::socket& socket,
                    std::function<void(const boost::system::error_code&, ByteVec)> cb);

void asyncWriteFrame(boost::asio::ip::tcp::socket& socket, ByteVec payload,
                     std::function<void(const boost::system::error_code&)> cb);

}  // namespace srp

