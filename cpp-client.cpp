#include "hex.h"
#include "noise.h"
#include <asio.hpp>
#include <coroutine>
#include <fmt/core.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

using asio::ip::tcp;
using namespace asio::ip;
using namespace asio;

awaitable<void> noise_test() {
  try {
    fmt::println("Retrieving executor");
    auto executor = co_await this_coro::executor;
    fmt::println("Instantiating socket");
    tcp::socket socket(executor);
    fmt::println("Attempting to establish connection");
    tcp::endpoint endpoint(address::from_string("127.0.0.1"), 3042);
    co_await socket.async_connect(endpoint, use_awaitable);
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
    fmt::println("Reading first message from socket");
    std::vector<std::uint8_t> read_buf, first_msg, second_msg;
    read_buf.resize(1024);
    first_msg.resize(1024);
    second_msg.resize(1024);
    co_await socket.async_read_some(buffer(read_buf, read_buf.size()),
                                    use_awaitable);
    fmt::println(
        "Attempting to perform first-phase key agreement with initiator pk");
    if (hs->read_message(read_buf, first_msg)) {
      throw std::runtime_error("A split wasn't expected yet!");
    }
    fmt::println("Transmitting our pk");
    std::vector<std::uint8_t> null_payload;
    if (hs->write_message(null_payload, second_msg)) {
      co_await socket.async_send(buffer(second_msg, second_msg.size()),
                                 use_awaitable);
      fmt::println("Initiation complete!");
      std::string hs_state;
      hs_state.resize(256);
      std::span<std::uint8_t> hs_view(
          reinterpret_cast<std::uint8_t *>(hs_state.data()), hs_state.size());
      const auto raw_hash = hs->get_handshake_hash();
      encodeHex(hs_view.data(), raw_hash.data(), raw_hash.size());
      fmt::println("Final handshake state hash: {}", hs_state);
      delete hs;
    } else {
      throw std::runtime_error(
          "Expected write_message to return two cipher states!");
    }
    // Now we're in business!
    // We don't save the two CSs, however, so we can't transmit anything, so we
    // don't. Instead, we just close the connection.
    socket.close();
    if (hs) {
      delete hs;
    }
  } catch (std::exception &e) {
    fmt::println("Error: {}", e.what());
  }
}

int main() {
  try {
    fmt::println("Instantiating context");
    io_context io_context;
    fmt::println("Spawning network coroutine");
    co_spawn(io_context, noise_test(), detached);
    fmt::println("Entering runloop");
    io_context.run();
    return 0;
  } catch (std::exception &e) {
    fmt::print("Error: {}\n", e.what());
    return 1;
  }
}