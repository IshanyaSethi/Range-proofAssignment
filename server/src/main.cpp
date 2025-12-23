#include <boost/asio.hpp>

#include <fstream>
#include <cctype>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include "srp/bytes.hpp"
#include "srp/crypto_utils.hpp"
#include "srp/session.hpp"

namespace srp {
namespace {

bool readTextFile(const std::string& path, std::string& out) {
  std::ifstream in(path);
  if (!in) return false;
  std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  out = std::move(s);
  return true;
}

std::string trim(std::string s) {
  auto is_ws = [](unsigned char c) { return std::isspace(c); };
  while (!s.empty() && is_ws(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && is_ws(static_cast<unsigned char>(s.back()))) s.pop_back();
  return s;
}

struct ServerConfig {
  ServerKeys keys;
  ClientRegistry registry;
};

ServerConfig defaultConfig() {
  ServerConfig cfg;

  // DEMO ONLY: never ship fixed private keys.
  cfg.keys.server_priv = toFixed<32>(hexToBytes(
      "0000000000000000000000000000000000000000000000000000000000000001"));
  cfg.keys.server_pub = pubkey33FromPriv(cfg.keys.server_priv);

  cfg.registry.clients.emplace(
      "DEMO-SERIAL-0001",
      toFixed<33>(hexToBytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")));
  return cfg;
}

ServerConfig loadConfig(const std::string& path) {
  ServerConfig cfg = defaultConfig();

  std::string raw;
  if (!readTextFile(path, raw)) {
    std::cerr << "config not found, using demo defaults: " << path << "\n";
    return cfg;
  }

  for (size_t i = 0; i < raw.size();) {
    size_t j = raw.find('\n', i);
    if (j == std::string::npos) j = raw.size();
    std::string line = trim(raw.substr(i, j - i));
    i = j + 1;
    if (line.empty() || line[0] == '#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    std::string key = trim(line.substr(0, eq));
    std::string val = trim(line.substr(eq + 1));

    try {
      if (key == "server_privkey_hex") {
        cfg.keys.server_priv = toFixed<32>(hexToBytes(val));
        cfg.keys.server_pub = pubkey33FromPriv(cfg.keys.server_priv);
      } else if (key.rfind("client.", 0) == 0 && key.size() > 7) {
        // client.<serial>.pubkey_hex=02....
        const std::string suffix = ".pubkey_hex";
        if (key.size() > suffix.size() &&
            key.compare(key.size() - suffix.size(), suffix.size(), suffix) == 0) {
          std::string serial = key.substr(7, key.size() - 7 - suffix.size());
          cfg.registry.clients[serial] = toFixed<33>(hexToBytes(val));
        }
      }
    } catch (const std::exception& e) {
      std::cerr << "config parse error for key=" << key << ": " << e.what() << "\n";
    }
  }

  return cfg;
}

}  // namespace
}  // namespace srp

int main(int argc, char** argv) {
  uint16_t port = 9000;
  std::string configPath = "server/config/server.conf";

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = static_cast<uint16_t>(std::stoi(argv[++i]));
    } else if (arg == "--config" && i + 1 < argc) {
      configPath = argv[++i];
    }
  }

  auto cfg = srp::loadConfig(configPath);

  boost::asio::io_context io;
  boost::asio::ip::tcp::acceptor acceptor(io, {boost::asio::ip::tcp::v4(), port});
  std::cout << "srp_server listening on port " << port << "\n";

  std::function<void()> doAccept;
  doAccept = [&]() {
    acceptor.async_accept([&](const boost::system::error_code& ec, boost::asio::ip::tcp::socket s) {
      if (!ec) {
        std::cout << "client connected from " << s.remote_endpoint() << "\n";
        std::make_shared<srp::Session>(std::move(s), cfg.keys, cfg.registry)->start();
      }
      doAccept();
    });
  };
  doAccept();
  io.run();
  return 0;
}

