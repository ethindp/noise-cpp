// The following demonstrates a Noise_XX_25519_ChaChaPoly_BLAKE2b handshake and
// initial transport messages.
#include "noise.h"
#include <algorithm>
#include <fmt/core.h>
#include <iomanip>
#include <iterator>
#include <ranges>
#include <sstream>
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

std::array<std::uint8_t, 32> from_hex(const std::string hex) {
  std::string s2;
  std::istringstream ss(hex);
  std::vector<std::uint8_t> msg;
  while ((ss >> std::setw(2) >> s2)) {
    unsigned u;
    std::istringstream ss2(s2);
    ss2 >> std::setbase(16) >> u;
    msg.push_back((uint8_t)u);
  }
  std::array<std::uint8_t, 32> msgout;
  for (auto i = 0; i < 32; ++i)
    msgout[i] = msg[i];
  return msgout;
}

int main() {
  try {
    auto alice_s = std::make_tuple(
        from_hex(
            "18bc6bbdfcc7860c11ba91ca0125413fe85925571d75b31749c21dbebbe68364"),
        from_hex("2429a9b297c44e1739368361f98d9a388e427931ac5c5c1f120f58856d58e"
                 "c07"));
    auto bob_s = std::make_tuple(
        from_hex(
            "68ae7e9626f8e5aee864e435fcbd279443378eb7f0ab140cfd1d6a373ec9865d"),
        from_hex("b149b4600ee3643252e7c74623f76d89939bd18c0bfc4518c2c95ce8c5cf9"
                 "d1e"));
    auto alice_handshakestate = noise::HandshakeState();
    auto bob_handshakestate = noise::HandshakeState();
    alice_handshakestate.initialize(noise::HandshakePattern::XX, true, {},
                                    alice_s);
    bob_handshakestate.initialize(noise::HandshakePattern::XX, false, {},
                                  bob_s);
    std::vector<std::uint8_t> sendbuf, recvbuf;
    sendbuf.reserve(65535);
    recvbuf.reserve(65535);
    while (!alice_handshakestate.is_handshake_finished()) {
      if (alice_handshakestate.is_my_turn()) {
        fmt::println("Initiator:");
        alice_handshakestate.write_message(sendbuf);
        fmt::println("Responder:");
        bob_handshakestate.read_message(sendbuf, recvbuf);
      } else {
        fmt::println("Responder:");
        bob_handshakestate.write_message(sendbuf);
        fmt::println("Initiator:");
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
