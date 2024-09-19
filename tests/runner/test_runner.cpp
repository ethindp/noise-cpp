#include "chex.h"
#include "choc_Files.h"
#include "choc_JSON.h"
#include "choc_StringUtilities.h"
#include "choc_Value.h"
#include "flags.h"
#include "magic_enum.hpp"
#include "monocypher.h"
#include "noise.h"
#include <algorithm>
#include <array>
#include <cstdint>
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

void run_tests(const std::string filename, const choc::value::Value);

int main(int argc, char **argv) {
  const flags::args args(argc, argv);
  if (args.positional().empty()) {
    fmt::println("Usage: {} <test files to run>", argv[0]);
    return 0;
  }
  for (const auto &file : args.positional()) {
    try {
      std::string filename{file};
      const auto contents = choc::file::loadFileAsString(filename);
      run_tests(filename, choc::json::parse(contents));
    } catch (std::exception &ex) {
      fmt::println("Error: could not run test {}: {}", file, ex.what());
      return 1;
    }
  }
  return 0;
}

void run_tests(const std::string filename,
               const choc::value::Value vectorlist) {
  const auto vectors = vectorlist["vectors"];
  std::uint64_t succeeded = 0, failed = 0, skipped = 0;
  for (std::uint32_t vector_idx = 0; vector_idx < vectors.size();
       ++vector_idx) {
    const auto vector = vectors[vector_idx];
    try {
      if (!vector["protocol_name"].isString() ||
          !vector.hasObjectMember("messages") || vector["hybrid"].isString() ||
          vector["fallback"].isBool() ||
          vector["fallback_pattern"].isString() ||
          vector["init_psks"].isVector() || vector["resp_psks"].isVector()) {
        fmt::println(
            "Warning: vector {} is missing protocol_name or messages field, or "
            "vector has one of "
            "hybrid/fallback/fallback_pattern/init_psks/resp_psks members",
            vector_idx);
        skipped++;
        continue;
      }
      for (std::uint32_t i = 0; i < vector["messages"].size(); ++i) {
        auto message = vector["messages"][i];
        if (!message.isObject()) {
          fmt::println(
              "Warning: in vector {} ({}), message {} is not an object",
              vector_idx, vector["protocol_name"].get<std::string>(), i);
          skipped += 1;
          goto skip_test;
        }
        if (!message["payload"].isString() ||
            !message["ciphertext"].isString()) {
          fmt::println("Warning: in vector {} ({}), message {} has no payload "
                       "or cipher text field, or either aren't strings",
                       vector_idx, vector["protocol_name"].get<std::string>(),
                       i);
          skipped += 1;
          goto skip_test;
        }
      }
      auto protocol_name_parts = choc::text::splitString(
          vector["protocol_name"].getString(), '_', false);
      auto [noise, handshake, dh, cipher, hash] =
          dissect<5>(protocol_name_parts);
      if (noise != "Noise" ||
          !magic_enum::enum_contains<noise::HandshakePattern>(handshake) ||
          dh != "25519" || cipher != "ChaChaPoly" || hash != "BLAKE2b") {
        fmt::println(
            "Warning: in vector {} ({}): unrecognized or unsupported protocol",
            vector_idx, vector["protocol_name"].get<std::string>());
        skipped++;
        continue;
      }
      std::vector<std::uint8_t> init_prologue, resp_prologue;
      std::array<std::uint8_t, 32> init_static, init_static_public,
          init_ephemeral, init_ephemeral_public, init_remote_static,
          resp_static, resp_static_public, resp_ephemeral,
          resp_ephemeral_public, resp_remote_static;
      std::array<std::uint8_t, 64> handshake_hash;
      bool init_static_inited = false, init_ephemeral_inited = false,
           init_remote_static_inited = false, resp_static_inited = false,
           resp_ephemeral_inited = false, resp_remote_static_inited = false,
           handshake_hash_inited = false;
      if (vector["init_prologue"].isString()) {
        std::string str = vector["init_prologue"].get<std::string>();
        init_prologue.resize(str.size() / 2);
        if (const auto size =
                chex_decode(init_prologue.data(), init_prologue.size(),
                            str.data(), str.size());
            size != init_prologue.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          init_prologue.size(), size));
        }
      }
      if (vector["resp_prologue"].isString()) {
        std::string str = vector["resp_prologue"].get<std::string>();
        resp_prologue.resize(str.size() / 2);
        if (const auto size =
                chex_decode(resp_prologue.data(), resp_prologue.size(),
                            str.data(), str.size());
            size != resp_prologue.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          init_prologue.size(), size));
        }
      }
      if (vector["init_static"].isString()) {
        std::string str = vector["init_static"].get<std::string>();
        if (const auto size = chex_decode(
                init_static.data(), init_static.size(), str.data(), str.size());
            size != init_static.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          init_static.size(), size));
        }
        crypto_x25519_public_key(init_static_public.data(), init_static.data());
        init_static_inited = true;
      }
      if (vector["init_ephemeral"].isString()) {
        std::string str = vector["init_ephemeral"].get<std::string>();
        if (const auto size =
                chex_decode(init_ephemeral.data(), init_ephemeral.size(),
                            str.data(), str.size());
            size != init_ephemeral.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          init_ephemeral.size(), size));
        }
        crypto_x25519_public_key(init_ephemeral_public.data(),
                                 init_ephemeral.data());
        init_ephemeral_inited = true;
      }
      if (vector["init_remote_static"].isString()) {
        std::string str = vector["init_remote_static"].get<std::string>();
        if (const auto size =
                chex_decode(init_remote_static.data(),
                            init_remote_static.size(), str.data(), str.size());
            size != init_remote_static.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          init_remote_static.size(), size));
        }
        init_remote_static_inited = true;
      }
      if (vector["resp_static"].isString()) {
        std::string str = vector["resp_static"].get<std::string>();
        if (const auto size = chex_decode(
                resp_static.data(), resp_static.size(), str.data(), str.size());
            size != resp_static.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          resp_static.size(), size));
        }
        crypto_x25519_public_key(resp_static_public.data(), resp_static.data());
        resp_static_inited = true;
      }
      if (vector["resp_ephemeral"].isString()) {
        std::string str = vector["resp_ephemeral"].get<std::string>();
        if (const auto size =
                chex_decode(resp_ephemeral.data(), resp_ephemeral.size(),
                            str.data(), str.size());
            size != resp_ephemeral.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          resp_ephemeral.size(), size));
        }
        crypto_x25519_public_key(resp_ephemeral_public.data(),
                                 resp_ephemeral.data());
        resp_ephemeral_inited = true;
      }
      if (vector["resp_remote_static"].isString()) {
        std::string str = vector["resp_remote_static"].get<std::string>();
        if (const auto size =
                chex_decode(resp_remote_static.data(),
                            resp_remote_static.size(), str.data(), str.size());
            size != resp_remote_static.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          resp_remote_static.size(), size));
        }
        resp_remote_static_inited = true;
      }
      if (vector["handshake_hash"].isString()) {
        std::string str = vector["handshake_hash"].get<std::string>();
        if (const auto size =
                chex_decode(handshake_hash.data(), handshake_hash.size(),
                            str.data(), str.size());
            size != handshake_hash.size()) {
          throw std::runtime_error(
              std::format("Hex decode error: did not decode {} bytes, only {}!",
                          handshake_hash.size(), size));
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
      alice.initialize(
          handshake_value, true, init_prologue,
          init_static_inited ? std::make_optional(std::make_tuple(
                                   init_static, init_static_public))
                             : std::nullopt,
          init_ephemeral_inited ? std::make_optional(std::make_tuple(
                                      init_ephemeral, init_ephemeral_public))
                                : std::nullopt,
          init_remote_static_inited ? std::make_optional(init_remote_static)
                                    : std::nullopt,
          std::nullopt);
      bob.initialize(
          handshake_value, false, resp_prologue,
          resp_static_inited ? std::make_optional(std::make_tuple(
                                   resp_static, resp_static_public))
                             : std::nullopt,
          resp_ephemeral_inited ? std::make_optional(std::make_tuple(
                                      resp_ephemeral, resp_ephemeral_public))
                                : std::nullopt,
          resp_remote_static_inited ? std::make_optional(resp_remote_static)
                                    : std::nullopt,
          std::nullopt);
      std::vector<std::uint8_t> sendbuf, recvbuf;
      sendbuf.resize(65535);
      recvbuf.resize(65535);
      std::deque<
          std::tuple<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>
          messages;
      for (const auto &message : vector["messages"]) {
        std::vector<std::uint8_t> payload_bytes, ciphertext_bytes;
        const std::string payload = message["payload"].get<std::string>();
        payload_bytes.resize(payload.size() / 2);
        if (const auto size =
                chex_decode(payload_bytes.data(), payload_bytes.size(),
                            payload.data(), payload.size());
            size != payload_bytes.size()) {
          throw std::runtime_error(std::format(
              "Could not decode payload! Expected {} bytes; got {}!",
              payload_bytes.size(), size));
        }
        const std::string ciphertext = message["ciphertext"].get<std::string>();
        ciphertext_bytes.resize(ciphertext.size() / 2);
        if (const auto size =
                chex_decode(ciphertext_bytes.data(), ciphertext_bytes.size(),
                            ciphertext.data(), ciphertext.size());
            size != ciphertext_bytes.size()) {
          throw std::runtime_error(std::format(
              "Could not decode ciphertext! Expected {} bytes; got {}!",
              ciphertext_bytes.size(), size));
        }
        messages.push_back({payload_bytes, ciphertext_bytes});
      }
      auto messages_iter = messages.begin();
      while (!alice.is_handshake_finished() ||
             messages_iter != messages.end()) {
        const auto i = std::distance(messages.begin(), messages_iter);
        auto [payload, ciphertext] = *messages_iter;
        sendbuf.clear();
        if (i % 2 == 0) {
          alice.write_message(payload, sendbuf);
          bob.read_message(sendbuf, recvbuf);
        } else {
          bob.write_message(payload, sendbuf);
          alice.read_message(sendbuf, recvbuf);
        }
        if (sendbuf != ciphertext || payload != recvbuf) {
          std::string plaintext_hex, ciphertext_hex, sendbuf_hex;
          plaintext_hex.resize(payload.size() * 2);
          ciphertext_hex.resize(ciphertext.size() * 2);
          sendbuf_hex.resize(sendbuf.size() * 2);
          chex_encode(plaintext_hex.data(), plaintext_hex.size(),
                      payload.data(), payload.size());
          chex_encode(ciphertext_hex.data(), ciphertext_hex.size(),
                      ciphertext.data(), ciphertext.size());
          chex_encode(sendbuf_hex.data(), sendbuf_hex.size(), sendbuf.data(),
                      sendbuf.size());
          throw std::logic_error(std::format(
              "In vector {}, message {}:\nplaintext: {}\nexpected: {}\nactual: "
              "{}",
              vector_idx, i, plaintext_hex, ciphertext_hex, sendbuf_hex));
        }
        messages_iter++;
      }
      if (!alice.is_handshake_finished() && messages_iter == messages.end()) {
        throw std::logic_error(
            "Reached end of messages buffer before handshake was complete!");
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
          chex_encode(plaintext_hex.data(), plaintext_hex.size(),
                      payload.data(), payload.size());
          chex_encode(ciphertext_hex.data(), ciphertext_hex.size(),
                      ciphertext.data(), ciphertext.size());
          chex_encode(sendbuf_hex.data(), sendbuf_hex.size(), sendbuf.data(),
                      sendbuf.size());
          chex_encode(recvbuf_hex.data(), recvbuf_hex.size(), recvbuf.data(),
                      recvbuf.size());
          throw std::logic_error(
              std::format("In vector {}, while communicating, message "
                          "{}:\nPlaintext: {}\nExpected ciphertext: {}\nActual "
                          "ciphertext: {}\nActual plaintext: {}",
                          vector_idx, i, plaintext_hex, ciphertext_hex,
                          sendbuf_hex, recvbuf_hex));
        }
      }
      succeeded += 1;
    } catch (std::logic_error &ex) {
      if (vector["fail"].isBool() && vector["fail"].getBool()) {
        succeeded += 1;
      } else {
        failed += 1;
        fmt::println("Warning: test {} failed: {}",
                     vector["name"].isString()
                         ? vector["name"].getString()
                         : vector["protocol_name"].getString(),
                     ex.what());
      }
    }
  skip_test:;
  }
  fmt::println("Tests from {} completed: {} succeeded, {} failed, {} skipped",
               filename, succeeded, failed, skipped);
}
