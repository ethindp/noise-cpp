// The following demonstrates a Noise_XX_25519_ChaChaPoly_BLAKE2b handshake and
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
    auto alice_s = noise::generate_keypair();
    auto bob_s = noise::generate_keypair();
    auto alice_handshakestate = noise::HandshakeState();
    auto bob_handshakestate = noise::HandshakeState();
    noise::HandshakeStateConfiguration alice_cfg;
    alice_cfg.pattern = noise::HandshakePattern::XX;
    alice_cfg.initiator = true;
    alice_cfg.s = alice_s;
    alice_handshakestate.initialize(alice_cfg);
    noise::HandshakeStateConfiguration bob_cfg;
    bob_cfg.pattern = noise::HandshakePattern::XX;
    bob_cfg.initiator = false;
    bob_cfg.s = bob_s;
    bob_handshakestate.initialize(bob_cfg);
    std::vector<std::uint8_t> sendbuf, recvbuf;
    sendbuf.reserve(65535);
    recvbuf.reserve(65535);
    while (!alice_handshakestate.is_handshake_finished()) {
      if (alice_handshakestate.is_my_turn()) {
        alice_handshakestate.write_message(sendbuf);
        bob_handshakestate.read_message(sendbuf, recvbuf);
      } else {
        bob_handshakestate.write_message(sendbuf);
        alice_handshakestate.read_message(sendbuf, recvbuf);
      }
    }
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
