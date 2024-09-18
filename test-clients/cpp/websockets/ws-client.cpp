#include "easywsclient.hpp"
#include "noise.h"
#include <algorithm>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <iomanip>
#include <iterator>
#include <optional>
#include <ranges>
#include <span>
#include <sstream>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif

int main() {
#ifdef _WIN32
  int rc;
  WSADATA wsaData;
  rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (rc) {
    fmt::println("WSAStartup Failed.");
    return 1;
  }
#endif
  bool done = false;
  try {
    fmt::println("Attempting to establish connection");
    auto client = easywsclient::WebSocket::from_url("ws://localhost:4000");
    fmt::println("Creating handshake state as non-initiator");
    noise::HandshakeState *hs = new noise::HandshakeState;
    if (!hs) {
      throw std::runtime_error("Handshake malloc failed!");
    }
    fmt::println("Initializing hs");
    hs->initialize(noise::HandshakePattern::NN, // Handshake pattern to use,
                                                // forms protocol name
                   false                        // We are not the initiator
                   // This function takes more args, but they are all optional
                   // and we don't need to set them in this instance
    );
    while (!done) {
      client->poll(-1);
      client->dispatchBinary([&](const std::vector<std::uint8_t> &message) {
        fmt::println("Reading first message from socket");
        std::vector<std::uint8_t> read_buf, first_msg, second_msg;
        std::ranges::copy(message, std::back_inserter(read_buf));
        first_msg.reserve(65535);
        second_msg.reserve(65535);
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        std::ranges::for_each(read_buf, [&](auto byte) {
          ss << std::setw(2) << static_cast<std::uint64_t>(byte);
        });
        fmt::println("Received message of length {} ({}) as hex: {}",
                     message.size(), read_buf.size(), ss.str());
        ss.str("");
        fmt::println("Attempting to perform first-phase key agreement with "
                     "initiator pk");
        if (hs->read_message(read_buf, first_msg)) {
          throw std::runtime_error("A split wasn't expected yet!");
        }
        fmt::println("Transmitting our pk");
        std::vector<std::uint8_t> null_payload;
        if (hs->write_message(null_payload, second_msg)) {
          client->sendBinary(second_msg);
          fmt::println("Initiation complete!");
          const auto raw_hash = hs->get_handshake_hash();
          ss << std::hex << std::setfill('0');
          std::ranges::for_each(raw_hash, [&](auto byte) {
            ss << std::setw(2) << static_cast<std::uint64_t>(byte);
          });
          fmt::println("Final handshake state hash: {}", ss.str());
        } else {
          throw std::runtime_error(
              "Expected write_message to return two cipher states!");
        }
        // Now we're in business!
        // We don't save the two CSs, however, so we can't transmit anything, so
        // we don't. Instead, we just close the connection.
        done = true;
      });
    }
    if (client) {
      client->close();
      client->poll(-1);
      if (client) {
        delete client;
      }
    }
    if (hs) {
      delete hs;
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
  } catch (std::exception &e) {
    fmt::println("Error: {}", e.what());
    return 1;
  }
}
