// The following demonstrates a Noise_NN_25519_ChaChaPoly_BLAKE2b handshake and
// initial transport messages.
#include "noise.h"
#include <algorithm>
#include <fmt/core.h>
#include <iterator>
#include <ranges>
#include <string>
#include <tuple>

std::vector<std::uint8_t> to_bytes(const std::string message) {
  std::vector<std::uint8_t> out(message.size(), 0);
  std::transform(message.begin(), message.end(), out.begin(),
                 [](const auto c) { return static_cast<std::uint8_t>(c); });
  return out;
}

std::string from_bytes(const std::vector<std::uint8_t> bytes) {
  std::string out;
  out.resize(bytes.size());
  std::transform(bytes.begin(), bytes.end(), out.begin(),
                 [](const auto c) { return static_cast<char>(c); });
  return out;
}

int main() {
  try {
    auto alice_handshakestate = noise::HandshakeState();
    auto bob_handshakestate = noise::HandshakeState();
    alice_handshakestate.initialize(noise::HandshakePattern::NN, true);
    bob_handshakestate.initialize(noise::HandshakePattern::NN, false);
    std::vector<std::uint8_t> read_buf, first_msg, second_msg;
    // -> e
    alice_handshakestate.write_message(first_msg);
    // Bob processes the first message...
    bob_handshakestate.read_message(first_msg, read_buf);
    // <- e, ee
    bob_handshakestate.write_message(second_msg);
    alice_handshakestate.read_message(second_msg, read_buf);
    auto alice_cipherstates = alice_handshakestate.finalize();
    auto bob_cipherstates = bob_handshakestate.finalize();
    auto [alice_send_cipher, alice_recv_cipher] = alice_cipherstates;
    auto [bob_recv_cipher, bob_send_cipher] = bob_cipherstates;
    // Alice to bob
    auto text = "Hello";
    auto text_bytes = to_bytes(text);
    alice_send_cipher.encrypt_with_ad(text_bytes);
    bob_recv_cipher.decrypt_with_ad(text_bytes);
    if (from_bytes(text_bytes) != text) {
      fmt::println("Oops, Alice couldn't communicate with Bob!");
      return 1;
    }
    // Bob to alice
    text = "World";
    text_bytes = to_bytes(text);
    bob_send_cipher.encrypt_with_ad(text_bytes);
    alice_recv_cipher.decrypt_with_ad(text_bytes);
    if (from_bytes(text_bytes) != text) {
      fmt::println("Oops, Bob couldn't communicate with Alice!");
      return 1;
    }
    fmt::println("Everything went okay!");
  } catch (const std::exception &ex) {
    fmt::println("Uh oh! Got this error from noise: {}", ex.what());
    return 1;
  }
  return 0;
}
