#include "chex.h"
#include "choc_Files.h"
#include "choc_StringUtilities.h"
#include "flags.h"
#include "glaze/glaze.hpp"
#include "magic_enum.hpp"
#include "monocypher.h"
#include "noise.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <exception>
#include <fmt/core.h>
#include <iterator>
#include <optional>
#include <ranges>
#include <string>
#include <tuple>

template <class T, std::size_t N> struct vector_binder {
  std::vector<T> &vec;

  template <std::size_t I> T &get() { return vec.at(I); }
};

namespace std {
template <class T, std::size_t N>
struct tuple_size<vector_binder<T, N>>
    : std::integral_constant<std::size_t, N> {};

template <std::size_t I, std::size_t N, class T>
struct tuple_element<I, vector_binder<T, N>> {
  using type = T;
};
} // namespace std

template <std::size_t N, class T> auto dissect(std::vector<T> &vec) {
  return vector_binder<T, N>{vec};
}

struct TestVectorMessage;

struct NoiseTestVector {
  std::optional<std::string> name, hybrid, fallback, fallback_pattern,
      init_static, init_ephemeral, init_remote_static, resp_static,
      resp_ephemeral, resp_remote_static, handshake_hash;
  std::string protocol_name, init_prologue, resp_prologue;
  bool fail;
  std::optional<std::vector<std::string>> init_psks, resp_psks;
  std::vector<TestVectorMessage> messages;
};

struct TestVectorMessage {
  std::string payload, ciphertext;
};

void run_test(NoiseTestVector);

int main(int argc, char **argv) {
  const flags::args args(argc, argv);
  if (args.positional().empty()) {
    fmt::println("Usage: {} <test file to run>", argv[0]);
    return 1;
  }
  if (args.positional().size() > 1) {
    fmt::println("Error: must only specify one file");
    return 1;
  }
  try {
    const auto arg{args.get<std::string>(0)};
    const auto filename{*arg};
    const auto contents = choc::file::loadFileAsString(filename);
    NoiseTestVector vec{};
    auto ec = glz::read_json(vec, contents);
    if (ec) {
      fmt::println("Error reading {}:\n{}", filename,
                   glz::format_error(ec, contents));
      return 1;
    }
    run_test(vec);
  } catch (std::exception &ex) {
    fmt::println("Error: could not run test: {}", ex.what());
    return 1;
  }
  return 0;
}

void run_test(const NoiseTestVector vector) {
  try {
    if (vector.fallback || vector.fallback_pattern || vector.hybrid) {
      fmt::println("Error: skipping test because it either is for noise pipes "
                   "or uses hybrrid encryption");
      std::exit(77);
    }
    auto protocol_name_parts =
        choc::text::splitString(vector.protocol_name, '_', false);
    auto [noise, handshake, dh, cipher, hash] = dissect<5>(protocol_name_parts);
    if (noise != "Noise" ||
        !magic_enum::enum_contains<noise::HandshakePattern>(handshake) ||
        dh != "25519" || cipher != "ChaChaPoly" || hash != "BLAKE2b") {
      fmt::println("Error: in vector {}: unrecognized or unsupported protocol",
                   vector.protocol_name);
      std::exit(1);
    }
    std::vector<std::uint8_t> init_prologue, resp_prologue;
    std::array<std::uint8_t, 32> init_static, init_static_public,
        init_ephemeral, init_ephemeral_public, init_remote_static, resp_static,
        resp_static_public, resp_ephemeral, resp_ephemeral_public,
        resp_remote_static;
    std::array<std::uint8_t, 64> handshake_hash;
    bool init_static_inited = false, init_ephemeral_inited = false,
         init_remote_static_inited = false, resp_static_inited = false,
         resp_ephemeral_inited = false, resp_remote_static_inited = false,
         handshake_hash_inited = false;
    init_prologue.resize(vector.init_prologue.size() / 2);
    if (const auto size = chex_decode(
            init_prologue.data(), init_prologue.size(),
            vector.init_prologue.data(), vector.init_prologue.size());
        size != init_prologue.size()) {
      fmt::println("Error: init prologue: Hex decode error: did not decode {} "
                   "bytes, only {}!",
                   init_prologue.size(), size);
      std::exit(1);
    }
    resp_prologue.resize(vector.resp_prologue.size() / 2);
    if (const auto size = chex_decode(
            resp_prologue.data(), resp_prologue.size(),
            vector.resp_prologue.data(), vector.resp_prologue.size());
        size != resp_prologue.size()) {
      fmt::println("Error: resp prologue: Hex decode error: did not decode {} "
                   "bytes, only {}!",
                   resp_prologue.size(), size);
      std::exit(1);
    }
    if (vector.init_static) {
      std::string str = *vector.init_static;
      if (const auto size = chex_decode(init_static.data(), init_static.size(),
                                        str.data(), str.size());
          size != init_static.size()) {
        fmt::println("Error: init static: Hex decode error: did not decode {} "
                     "bytes, only {}!",
                     init_static.size(), size);
        std::exit(1);
      }
      crypto_x25519_public_key(init_static_public.data(), init_static.data());
      init_static_inited = true;
    }
    if (vector.init_ephemeral) {
      std::string str = *vector.init_ephemeral;
      if (const auto size =
              chex_decode(init_ephemeral.data(), init_ephemeral.size(),
                          str.data(), str.size());
          size != init_ephemeral.size()) {
        fmt::println("Error: init ephemeral: Hex decode error: did not decode "
                     "{} bytes, only {}!",
                     init_ephemeral.size(), size);
        std::exit(1);
      }
      crypto_x25519_public_key(init_ephemeral_public.data(),
                               init_ephemeral.data());
      init_ephemeral_inited = true;
    }
    if (vector.init_remote_static) {
      std::string str = *vector.init_remote_static;
      if (const auto size =
              chex_decode(init_remote_static.data(), init_remote_static.size(),
                          str.data(), str.size());
          size != init_remote_static.size()) {
        fmt::println("Error: init remote static: Hex decode error: did not "
                     "decode {} bytes, only {}!",
                     init_remote_static.size(), size);
        std::exit(1);
      }
      init_remote_static_inited = true;
    }
    if (vector.resp_static) {
      std::string str = *vector.resp_static;
      if (const auto size = chex_decode(resp_static.data(), resp_static.size(),
                                        str.data(), str.size());
          size != resp_static.size()) {
        fmt::println("Error: resp static: Hex decode error: did not decode {} "
                     "bytes, only {}!",
                     resp_static.size(), size);
        std::exit(1);
      }
      crypto_x25519_public_key(resp_static_public.data(), resp_static.data());
      resp_static_inited = true;
    }
    if (vector.resp_ephemeral) {
      std::string str = *vector.resp_ephemeral;
      if (const auto size =
              chex_decode(resp_ephemeral.data(), resp_ephemeral.size(),
                          str.data(), str.size());
          size != resp_ephemeral.size()) {
        fmt::println("Error: resp ephemeral: Hex decode error: did not decode "
                     "{} bytes, only {}!",
                     resp_static.size(), size);
        std::exit(1);
      }
      crypto_x25519_public_key(resp_ephemeral_public.data(),
                               resp_ephemeral.data());
      resp_ephemeral_inited = true;
    }
    if (vector.resp_remote_static) {
      std::string str = *vector.resp_remote_static;
      if (const auto size =
              chex_decode(resp_remote_static.data(), resp_remote_static.size(),
                          str.data(), str.size());
          size != resp_remote_static.size()) {
        fmt::println("Error: resp remote static: Hex decode error: did not "
                     "decode {} bytes, only {}!",
                     resp_remote_static.size(), size);
        std::exit(1);
      }
      resp_remote_static_inited = true;
    }
    if (vector.handshake_hash) {
      std::string str = *vector.handshake_hash;
      if (const auto size =
              chex_decode(handshake_hash.data(), handshake_hash.size(),
                          str.data(), str.size());
          size != handshake_hash.size()) {
        fmt::println("Error: handshake hash: Hex decode error: did not decode "
                     "{} bytes, only {}!",
                     handshake_hash.size(), size);
        std::exit(1);
      }
      handshake_hash_inited = true;
    }
    auto alice = noise::HandshakeState();
    auto bob = noise::HandshakeState();
    const auto handshake_value =
        magic_enum::enum_cast<noise::HandshakePattern>(handshake).value();
    const bool is_oneway = handshake_value == noise::HandshakePattern::N ||
                           handshake_value == noise::HandshakePattern::K ||
                           handshake_value == noise::HandshakePattern::X;
    switch (handshake_value) {
      using enum noise::HandshakePattern;
    case N:
    case X:
    case KN:
    case NK:
    case KX:
    case XK:
    case IK:
    case NK1:
    case X1K:
    case XK1:
    case X1K1:
    case K1N:
    case K1X:
    case KX1:
    case K1X1:
    case I1K:
    case IK1:
    case I1K1: {
      alice.initialize(handshake_value, true, init_prologue, std::nullopt,
                       std::nullopt, resp_static, std::nullopt);
      bob.initialize(handshake_value, false, resp_prologue,
                     std::make_tuple(resp_static, resp_static_public));
    } break;
    case K:
    case KK:
    case K1K:
    case KK1:
    case K1K1: {
      alice.initialize(handshake_value, true, init_prologue,
                       std::make_tuple(init_static, init_static_public),
                       std::nullopt, init_remote_static);
      bob.initialize(handshake_value, false, resp_prologue,
                     std::make_tuple(resp_static, resp_static_public),
                     std::nullopt, resp_remote_static);
    } break;
    default: {
      alice.initialize(handshake_value, true, init_prologue,
                       std::make_tuple(init_static, init_static_public),
                       std::nullopt, init_remote_static, std::nullopt);
      bob.initialize(handshake_value, false, resp_prologue,
                     std::make_tuple(resp_static, resp_static_public),
                     std::nullopt, resp_remote_static, std::nullopt);
    } break;
    }
    std::vector<std::uint8_t> sendbuf, recvbuf;
    sendbuf.resize(65535);
    recvbuf.resize(65535);
    std::deque<std::tuple<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>
        messages;
    for (const auto &message : vector.messages) {
      std::vector<std::uint8_t> payload_bytes, ciphertext_bytes;
      payload_bytes.resize(message.payload.size() / 2);
      if (const auto size =
              chex_decode(payload_bytes.data(), payload_bytes.size(),
                          message.payload.data(), message.payload.size());
          size != payload_bytes.size()) {
        fmt::println("Could not decode payload! Expected {} bytes, but got {}",
                     payload_bytes.size(), size);
        std::exit(1);
      }
      ciphertext_bytes.resize(message.ciphertext.size() / 2);
      if (const auto size =
              chex_decode(ciphertext_bytes.data(), ciphertext_bytes.size(),
                          message.ciphertext.data(), message.ciphertext.size());
          size != ciphertext_bytes.size()) {
        fmt::println(
            "Error: could not decode ciphertext! Expected {} bytes, got {}",
            ciphertext_bytes.size(), size);
        std::exit(1);
      }
      messages.push_back({payload_bytes, ciphertext_bytes});
    }
    auto messages_iter = messages.begin();
    while (!alice.is_handshake_finished() || messages_iter != messages.end()) {
      const auto i = std::distance(messages.begin(), messages_iter);
      auto [payload, ciphertext] = *messages_iter;
      std::vector<std::uint8_t> old_payload;
      std::ranges::copy(payload, std::back_inserter(old_payload));
      sendbuf.clear();
      if (alice.is_my_turn()) {
        alice.write_message(payload, sendbuf);
        bob.read_message(sendbuf, recvbuf);
      } else {
        bob.write_message(payload, sendbuf);
        alice.read_message(sendbuf, recvbuf);
      }
      if (sendbuf != ciphertext || old_payload != recvbuf) {
        std::string plaintext_hex, ciphertext_hex, sendbuf_hex;
        plaintext_hex.resize(payload.size() * 2);
        ciphertext_hex.resize(ciphertext.size() * 2);
        sendbuf_hex.resize(sendbuf.size() * 2);
        chex_encode(plaintext_hex.data(), plaintext_hex.size(), payload.data(),
                    payload.size());
        chex_encode(ciphertext_hex.data(), ciphertext_hex.size(),
                    ciphertext.data(), ciphertext.size());
        chex_encode(sendbuf_hex.data(), sendbuf_hex.size(), sendbuf.data(),
                    sendbuf.size());
        fmt::println("Error: vector {}, message {}:\nplaintext: {}\nexpected: "
                     "{}\nactual: {}",
                     vector.protocol_name, i, plaintext_hex, ciphertext_hex,
                     sendbuf_hex);
        std::exit(vector.fail ? 99 : 1);
      }
      messages_iter++;
    }
    if (!alice.is_handshake_finished() && messages_iter == messages.end()) {
      fmt::println(
          "Reached end of messages buffer before handshake was complete!");
      std::exit(1);
    }
    // This definitely shouldn't fail, and if it does something is wrong
    auto alice_cipherstates = alice.finalize();
    auto bob_cipherstates = bob.finalize();
    for (auto i = 0; i < messages.size(); ++i) {
      const auto [payload, ciphertext] = messages[i];
      auto [alice_send_cipher, alice_recv_cipher] = alice_cipherstates;
      auto [bob_recv_cipher, bob_send_cipher] = bob_cipherstates;
      if (is_oneway || i % 2 == 0) {
        sendbuf = payload;
        alice_send_cipher.encrypt_with_ad(sendbuf);
        recvbuf = sendbuf;
        bob_recv_cipher.decrypt_with_ad(recvbuf);
      } else {
        sendbuf = payload;
        bob_send_cipher.encrypt_with_ad(sendbuf);
        recvbuf = sendbuf;
        alice_recv_cipher.decrypt_with_ad(recvbuf);
      }
      if (sendbuf != ciphertext || payload != recvbuf) {
        std::string plaintext_hex, ciphertext_hex, sendbuf_hex, recvbuf_hex;
        plaintext_hex.resize(payload.size() * 2);
        ciphertext_hex.resize(ciphertext.size() * 2);
        sendbuf_hex.resize(sendbuf.size() * 2);
        recvbuf_hex.resize(recvbuf.size() * 2);
        chex_encode(plaintext_hex.data(), plaintext_hex.size(), payload.data(),
                    payload.size());
        chex_encode(ciphertext_hex.data(), ciphertext_hex.size(),
                    ciphertext.data(), ciphertext.size());
        chex_encode(sendbuf_hex.data(), sendbuf_hex.size(), sendbuf.data(),
                    sendbuf.size());
        chex_encode(recvbuf_hex.data(), recvbuf_hex.size(), recvbuf.data(),
                    recvbuf.size());
        fmt::println("Error: in vector {}, while communicating, message "
                     "{}:\nPlaintext: {}\nExpected ciphertext: {}\nActual "
                     "ciphertext: {}\nActual plaintext: {}",
                     vector.protocol_name, i, plaintext_hex, ciphertext_hex,
                     sendbuf_hex, recvbuf_hex);
        std::exit(vector.fail ? 99 : 1);
      }
    }
  } catch (std::logic_error &ex) {
    fmt::println("Error: test {} failed: {}",
                 vector.name ? *vector.name : vector.protocol_name, ex.what());
  }
}
