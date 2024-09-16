#include "noise.h"
#include "magic_enum.hpp"
#include "monocypher-ed25519.h"
#include "monocypher.h"
#include "rng_get_bytes.h"
#include <algorithm>
#include <array>
#include <deque>
#include <format>
#include <iterator>
#include <limits>
#include <optional>
#include <ranges>
#include <span>
#include <stack>
#include <stdexcept>
#include <tuple>
#include <vector>

namespace noise {
std::tuple<std::array<std::uint8_t, 32>, std::array<std::uint8_t, 32>>
generate_keypair() {
  std::array<std::uint8_t, 32> privkey, pubkey;
  while (rng_get_bytes(privkey.data(), 32) != 32)
    ;
  crypto_x25519_public_key(pubkey.data(), privkey.data());
  return {privkey, pubkey};
}

template <STLContainer T> T dh(const T &privkey, const T &pubkey) {
  T secret;
  crypto_x25519(secret.data(), privkey.data(), pubkey.data());
  return secret;
}

template <STLContainer T1, STLContainer T2>
void encrypt(T1 &k, std::uint64_t n, std::optional<T2> ad, T2 &in_out) {
  const auto text_size = in_out.size();
  in_out.resize(in_out.size() + 16);
  std::span<std::uint8_t> plaintext(in_out.data(), text_size);
  std::span<std::uint8_t> mac(in_out.data() + text_size, 16);
  std::array<std::uint8_t, 12> nonce;
  std::ranges::fill(nonce, 0);
  nonce[4] = (n >> (8 * 0)) & 0xff;
  nonce[5] = (n >> (8 * 1)) & 0xff;
  nonce[6] = (n >> (8 * 2)) & 0xff;
  nonce[7] = (n >> (8 * 3)) & 0xff;
  nonce[8] = (n >> (8 * 4)) & 0xff;
  nonce[9] = (n >> (8 * 5)) & 0xff;
  nonce[10] = (n >> (8 * 6)) & 0xff;
  nonce[11] = (n >> (8 * 7)) & 0xff;
  crypto_aead_ctx ctx;
  crypto_aead_init_ietf(&ctx, k.data(), nonce.data());
  crypto_aead_write(&ctx, plaintext.data(), mac.data(),
                    ad ? ad->data() : nullptr, ad ? ad->size() : 0,
                    plaintext.data(), text_size);
  crypto_wipe(&ctx, sizeof(ctx));
  crypto_wipe(k.data(), k.size());
  crypto_wipe(nonce.data(), nonce.size());
}

void encrypt(std::array<std::uint8_t, 32> &k, std::uint64_t n,
             std::optional<std::vector<std::uint8_t>> ad,
             std::vector<std::uint8_t> &in_out) {
  const auto text_size = in_out.size();
  in_out.resize(in_out.size() + 16);
  std::span<std::uint8_t> plaintext(in_out.data(), text_size);
  std::span<std::uint8_t> mac(in_out.data() + text_size, 16);
  std::array<std::uint8_t, 12> nonce;
  std::ranges::fill(nonce, 0);
  nonce[4] = (n >> (8 * 0)) & 0xff;
  nonce[5] = (n >> (8 * 1)) & 0xff;
  nonce[6] = (n >> (8 * 2)) & 0xff;
  nonce[7] = (n >> (8 * 3)) & 0xff;
  nonce[8] = (n >> (8 * 4)) & 0xff;
  nonce[9] = (n >> (8 * 5)) & 0xff;
  nonce[10] = (n >> (8 * 6)) & 0xff;
  nonce[11] = (n >> (8 * 7)) & 0xff;
  crypto_aead_ctx ctx;
  crypto_aead_init_ietf(&ctx, k.data(), nonce.data());
  crypto_aead_write(&ctx, plaintext.data(), mac.data(),
                    ad ? ad->data() : nullptr, ad ? ad->size() : 0,
                    plaintext.data(), text_size);
  crypto_wipe(&ctx, sizeof(ctx));
  crypto_wipe(k.data(), k.size());
  crypto_wipe(nonce.data(), nonce.size());
}

template <STLContainer T1, STLContainer T2>
void decrypt(T1 &k, std::uint64_t n, std::optional<T2> ad, T2 &in_out) {
  const auto text_size = in_out.size() - 16;
  std::span<std::uint8_t> ciphertext(in_out.data(), text_size);
  std::span<std::uint8_t> mac(in_out.data() + text_size, 16);
  std::array<std::uint8_t, 12> nonce;
  std::ranges::fill(nonce, 0);
  nonce[4] = (n >> (8 * 0)) & 0xff;
  nonce[5] = (n >> (8 * 1)) & 0xff;
  nonce[6] = (n >> (8 * 2)) & 0xff;
  nonce[7] = (n >> (8 * 3)) & 0xff;
  nonce[8] = (n >> (8 * 4)) & 0xff;
  nonce[9] = (n >> (8 * 5)) & 0xff;
  nonce[10] = (n >> (8 * 6)) & 0xff;
  nonce[11] = (n >> (8 * 7)) & 0xff;
  crypto_aead_ctx ctx;
  crypto_aead_init_ietf(&ctx, k.data(), nonce.data());
  if (crypto_aead_read(&ctx, ciphertext.data(), mac.data(),
                       ad ? ad->data() : nullptr, ad ? ad->size() : 0,
                       ciphertext.data(), text_size) == -1) {
    crypto_wipe(&ctx, sizeof(ctx));
    crypto_wipe(k.data(), k.size());
    crypto_wipe(nonce.data(), nonce.size());
    throw std::invalid_argument("Invalid MAC");
  }
  crypto_wipe(&ctx, sizeof(ctx));
  crypto_wipe(k.data(), k.size());
  crypto_wipe(nonce.data(), nonce.size());
}

void decrypt(std::array<std::uint8_t, 32> &k, std::uint64_t n,
             std::optional<std::vector<std::uint8_t>> ad,
             std::vector<std::uint8_t> &in_out) {
  const auto text_size = in_out.size() - 16;
  std::span<std::uint8_t> ciphertext(in_out.data(), text_size);
  std::span<std::uint8_t> mac(in_out.data() + text_size, 16);
  std::array<std::uint8_t, 12> nonce;
  std::ranges::fill(nonce, 0);
  nonce[4] = (n >> (8 * 0)) & 0xff;
  nonce[5] = (n >> (8 * 1)) & 0xff;
  nonce[6] = (n >> (8 * 2)) & 0xff;
  nonce[7] = (n >> (8 * 3)) & 0xff;
  nonce[8] = (n >> (8 * 4)) & 0xff;
  nonce[9] = (n >> (8 * 5)) & 0xff;
  nonce[10] = (n >> (8 * 6)) & 0xff;
  nonce[11] = (n >> (8 * 7)) & 0xff;
  crypto_aead_ctx ctx;
  crypto_aead_init_ietf(&ctx, k.data(), nonce.data());
  if (crypto_aead_read(&ctx, ciphertext.data(), mac.data(),
                       ad ? ad->data() : nullptr, ad ? ad->size() : 0,
                       ciphertext.data(), text_size) == -1) {
    crypto_wipe(&ctx, sizeof(ctx));
    crypto_wipe(k.data(), k.size());
    crypto_wipe(nonce.data(), nonce.size());
    throw std::invalid_argument("Invalid MAC");
  }
  crypto_wipe(&ctx, sizeof(ctx));
  crypto_wipe(k.data(), k.size());
  crypto_wipe(nonce.data(), nonce.size());
}

template <STLContainer T1, STLContainer T2> T1 hash(const T2 &input) {
  T1 hash;
  crypto_blake2b(hash.data(), hash.size(), input.data(), input.size());
  return hash;
}

std::array<std::uint8_t, 64> hmac_hash(std::array<std::uint8_t, 64> &key,
                                       const std::vector<std::uint8_t> &input) {
  std::array<std::uint8_t, 64> hmac;
  if (key.size() > 128) {
    crypto_blake2b(key.data(), 64, key.data(), key.size());
  }
  std::array<std::uint8_t, 128> temp_key;
  for (auto i = 0; i < 64; ++i) {
    temp_key[i] = key[i] ^ 0x36;
  }
  for (auto i = 64; i < 128; ++i) {
    temp_key[i] = 0x36;
  }
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, 64);
  crypto_blake2b_update(&ctx, temp_key.data(), 128);
  crypto_blake2b_update(&ctx, input.data(), input.size());
  crypto_blake2b_final(&ctx, hmac.data());
  crypto_wipe(&ctx, sizeof(ctx));
  for (auto i = 0; i < 128; ++i) {
    temp_key[i] ^= 0x36 ^ 0x5c;
  }
  crypto_blake2b_init(&ctx, 64);
  crypto_blake2b_update(&ctx, temp_key.data(), 128);
  crypto_blake2b_update(&ctx, hmac.data(), 64);
  crypto_blake2b_final(&ctx, hmac.data());
  crypto_wipe(&ctx, sizeof(ctx));
  crypto_wipe(key.data(), key.size());
  return hmac;
}

std::array<std::uint8_t, 64>
hmac_hash(std::array<std::uint8_t, 64> &key,
          const std::array<std::uint8_t, 32> &input) {
  std::array<std::uint8_t, 64> hmac;
  if (key.size() > 128) {
    crypto_blake2b(key.data(), 64, key.data(), key.size());
  }
  std::array<std::uint8_t, 128> temp_key;
  for (auto i = 0; i < 64; ++i) {
    temp_key[i] = key[i] ^ 0x36;
  }
  for (auto i = 64; i < 128; ++i) {
    temp_key[i] = 0x36;
  }
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, 64);
  crypto_blake2b_update(&ctx, temp_key.data(), 128);
  crypto_blake2b_update(&ctx, input.data(), input.size());
  crypto_blake2b_final(&ctx, hmac.data());
  crypto_wipe(&ctx, sizeof(ctx));
  for (auto i = 0; i < 128; ++i) {
    temp_key[i] ^= 0x36 ^ 0x5c;
  }
  crypto_blake2b_init(&ctx, 64);
  crypto_blake2b_update(&ctx, temp_key.data(), 128);
  crypto_blake2b_update(&ctx, hmac.data(), 64);
  crypto_blake2b_final(&ctx, hmac.data());
  crypto_wipe(&ctx, sizeof(ctx));
  crypto_wipe(key.data(), key.size());
  return hmac;
}

template <STLContainer T1, STLContainer T2>
void hkdf(T1 &chaining_key, T2 &input_key_material, T1 &out1, T1 &out2) {
  auto temp_key = hmac_hash(chaining_key, input_key_material);
  out1 = hmac_hash(temp_key, std::vector<std::uint8_t>{0x01});
  std::vector<std::uint8_t> tmp1;
  tmp1.insert(tmp1.end(), out1.begin(), out1.end());
  tmp1.push_back(0x02);
  out2 = hmac_hash(temp_key, tmp1);
  crypto_wipe(temp_key.data(), temp_key.size());
}

template <STLContainer T1, STLContainer T2>
void hkdf(T1 &chaining_key, T2 &input_key_material, T1 &out1, T1 &out2,
          T1 &out3) {
  auto temp_key = hmac_hash(chaining_key, input_key_material);
  out1 = hmac_hash(temp_key, std::vector<std::uint8_t>{0x01});
  std::vector<std::uint8_t> tmp1;
  tmp1.insert(tmp1.end(), out1.begin(), out1.end());
  tmp1.push_back(0x02);
  out2 = hmac_hash(temp_key, tmp1);
  std::vector<std::uint8_t> tmp2;
  tmp2.insert(tmp2.end(), out2.begin(), out2.end());
  tmp2.push_back(0x03);
  out3 = hmac_hash(temp_key, tmp2);
  crypto_wipe(temp_key.data(), temp_key.size());
}

CipherState::~CipherState() {
  crypto_wipe(k.data(), k.size());
  n = std::numeric_limits<std::uint64_t>::max();
}

void CipherState::initialize_key(const std::array<std::uint8_t, 32> &key) {
  k = key;
  n = 0;
}

bool CipherState::has_key() const {
  return !std::ranges::all_of(k, [](const auto &el) { return el == 0; });
}

void CipherState::set_nonce(const std::uint64_t &nonce) { n = nonce; }

template <STLContainer T>
void CipherState::encrypt_with_ad(T &ad, T &plaintext) {
  if (!has_key()) {
    throw std::logic_error("Attempted to encrypt without a key!");
  }
  if (n == std::numeric_limits<std::uint64_t>::max() - 1) {
    throw std::out_of_range("Nonce limit has been exceeded!");
  }
  encrypt(k, n++, ad, plaintext);
}

template <STLContainer T>
void CipherState::decrypt_with_ad(T &ad, T &ciphertext) {
  if (!has_key()) {
    throw std::logic_error("Attempted to decrypt without a key!");
  }
  if (n == std::numeric_limits<std::uint64_t>::max() - 1) {
    throw std::out_of_range("Nonce limit has been exceeded!");
  }
  decrypt(k, n++, ad, ciphertext);
}

SymmetricState::~SymmetricState() {
  crypto_wipe(ck.data(), ck.size());
  crypto_wipe(h.data(), h.size());
}

void SymmetricState::initialize_symmetric(
    const std::vector<std::uint8_t> &protocol_name) {
  if (protocol_name.size() <= 64) {
    std::ranges::copy_n(protocol_name.begin(), protocol_name.size(), h.begin());
    for (auto i = protocol_name.size(); i < h.size(); ++i) {
      h[i] = 0;
    }
  } else {
    h = hash<std::array<std::uint8_t, 64>, std::vector<std::uint8_t>>(
        protocol_name);
  }
  ck = h;
  std::array<std::uint8_t, 32> key;
  std::ranges::fill(key, 0);
  cs.initialize_key(key);
  crypto_wipe(key.data(), key.size());
}

template <STLContainer T> void SymmetricState::mix_key(T &input_key_material) {
  std::array<std::uint8_t, 64> temp_k;
  hkdf(ck, input_key_material, ck, temp_k);
  std::array<std::uint8_t, 32> truncated_k;
  std::ranges::copy_n(temp_k.begin(), 32, truncated_k.begin());
  crypto_wipe(temp_k.data(), temp_k.size());
  cs.initialize_key(truncated_k);
  crypto_wipe(truncated_k.data(), truncated_k.size());
  crypto_wipe(input_key_material.data(), input_key_material.size());
}

template <STLContainer T> void SymmetricState::mix_hash(const T &data) {
  // Here we reimplement hash() because it's much simpler and probably safer
  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, h.size());
  crypto_blake2b_update(&ctx, h.data(), h.size());
  crypto_blake2b_update(&ctx, data.data(), data.size());
  crypto_blake2b_final(&ctx, h.data());
  crypto_wipe(&ctx, sizeof(ctx));
}

std::array<std::uint8_t, 64> SymmetricState::get_handshake_hash() const {
  return h;
}

template <STLContainer T> void SymmetricState::encrypt_and_hash(T &plaintext) {
  std::vector<std::uint8_t> ad;
  ad.resize(h.size());
  std::ranges::copy(h, ad.begin());
  cs.encrypt_with_ad(ad, plaintext);
  mix_hash(plaintext);
}

template <STLContainer T> void SymmetricState::decrypt_and_hash(T &ciphertext) {
  std::vector<std::uint8_t> ad;
  ad.resize(h.size());
  std::ranges::copy(h, ad.begin());
  cs.decrypt_with_ad(ad, ciphertext);
  mix_hash(ciphertext);
}

std::tuple<CipherState, CipherState> SymmetricState::split() {
  std::array<std::uint8_t, 64> temp_k1, temp_k2;
  std::vector<std::uint8_t> zerolen;
  hkdf(ck, zerolen, temp_k1, temp_k2);
  std::array<std::uint8_t, 32> actual_k1, actual_k2;
  std::ranges::copy_n(temp_k1.begin(), 32, actual_k1.begin());
  std::ranges::copy_n(temp_k2.begin(), 32, actual_k2.begin());
  crypto_wipe(temp_k1.data(), temp_k1.size());
  crypto_wipe(temp_k2.data(), temp_k2.size());
  CipherState c1, c2;
  c1.initialize_key(actual_k1);
  c2.initialize_key(actual_k2);
  crypto_wipe(actual_k1.data(), actual_k1.size());
  crypto_wipe(actual_k2.data(), actual_k2.size());
  return {c1, c2};
}

bool SymmetricState::cs_has_key() const { return cs.has_key(); }

HandshakeState::~HandshakeState() {
  crypto_wipe(spk.data(), spk.size());
  crypto_wipe(ssk.data(), ssk.size());
  crypto_wipe(epk.data(), epk.size());
  crypto_wipe(rspk.data(), rspk.size());
  crypto_wipe(repk.data(), repk.size());
  crypto_wipe(esk.data(), esk.size());
}

void HandshakeState::initialize(
    const HandshakePattern &handshake_pattern, const bool &i,
    const std::vector<std::uint8_t> prologue,
    std::optional<
        std::tuple<std::array<std::uint8_t, 32>, std::array<std::uint8_t, 32>>>
        s,
    std::optional<
        std::tuple<std::array<std::uint8_t, 32>, std::array<std::uint8_t, 32>>>
        e,
    std::optional<std::array<std::uint8_t, 32>> rs,
    std::optional<std::array<std::uint8_t, 32>> re) {
  const auto protocol_name_str =
      std::format("Noise_{}_25519_ChaChaPoly_BLAKE2b",
                  magic_enum::enum_name(handshake_pattern));
  if (protocol_name_str.size() > 255) {
    throw std::length_error("Protocol name too long");
  }
  std::vector<std::uint8_t> protocol_name;
  protocol_name.resize(protocol_name_str.size());
  std::transform(
      protocol_name_str.begin(), protocol_name_str.end(), protocol_name.begin(),
      [](const auto &chr) { return static_cast<std::uint8_t>(chr); });
  ss.initialize_symmetric(protocol_name);
  ss.mix_hash(prologue);
  initiator = i;
  if (s) {
    const auto &[sk, pk] = *s;
    ssk = sk;
    spk = pk;
  }
  if (e) {
    const auto &[sk, pk] = *e;
    esk = sk;
    epk = pk;
  }
  if (rs) {
    rspk = *rs;
  }
  if (re) {
    repk = *re;
  }
  if (s) {
    ss.mix_hash(spk);
  }
  if (e) {
    ss.mix_hash(epk);
  }
  if (rs) {
    ss.mix_hash(rspk);
  }
  if (re) {
    ss.mix_hash(repk);
  }
  using enum PatternToken;
  using enum HandshakePattern;
  switch (handshake_pattern) {
  case K:
    message_patterns = {{S}, {S}, {E, Es, Ss}};
    break;
  case KK:
    message_patterns = {{S}, {S}, {E, Es, Ss}, {E, Ee, Se}};
    break;
  case KN:
    message_patterns = {{S}, {E}, {E, Ee, Se}};
    break;
  case KX:
    message_patterns = {{S}, {E}, {E, Ee, Se, S, Es}};
    break;
  case N:
    message_patterns = {{S}, {E, Es}};
    break;
  case NK:
    message_patterns = {{S}, {E, Es}, {E, Ee}};
    break;
  case NN:
    message_patterns = {{E}, {E, Ee}};
    break;
  case NX:
    message_patterns = {{E}, {E, Ee, S, Es}};
    break;
  case XK:
    message_patterns = {{S}, {E, Es}, {E, Ee}, {S, Se}};
    break;
  case XN:
    message_patterns = {{E, Ee}, {S, Se}};
    break;
  case XX:
    message_patterns = {{E}, {E, Ee, S, Es}, {S, Se}};
    break;
  }
}

std::optional<std::tuple<CipherState, CipherState>>
HandshakeState::write_message(std::vector<std::uint8_t> &payload,
                              std::vector<std::uint8_t> &message_buffer) {
  if (!message_patterns.empty()) {
    const auto &current_pattern = message_patterns.front();
    for (const auto &token : current_pattern) {
      using enum PatternToken;
      switch (token) {
      case E: {
        auto [sk, pk] = generate_keypair();
        std::ranges::move(sk, esk.begin());
        std::ranges::move(pk, epk.begin());
        crypto_wipe(sk.data(), sk.size());
        crypto_wipe(pk.data(), pk.size());
        std::ranges::copy(epk, std::back_inserter(message_buffer));
        ss.mix_hash(epk);
      } break;
      case S:
        std::ranges::copy(spk, std::back_inserter(message_buffer));
        break;
      case Ee: {
        auto dhres = dh(esk, repk);
        ss.mix_key(dhres);
        crypto_wipe(dhres.data(), dhres.size());
      } break;
      case Es: {
        std::array<std::uint8_t, 32> key;
        if (initiator) {
          key = dh(esk, rspk);
        } else {
          key = dh(ssk, repk);
        }
        ss.mix_key(key);
        crypto_wipe(key.data(), key.size());
      } break;
      case Se: {
        std::array<std::uint8_t, 32> key;
        if (initiator) {
          key = dh(ssk, repk);
        } else {
          key = dh(esk, rspk);
        }
        ss.mix_key(key);
        crypto_wipe(key.data(), key.size());
      } break;
      case Ss: {
        auto dhres = dh(ssk, rspk);
        ss.mix_key(dhres);
        crypto_wipe(dhres.data(), dhres.size());
      } break;
      }
    }
    message_patterns.pop_front();
  }
  ss.encrypt_and_hash(payload);
  std::ranges::move(payload, std::back_inserter(message_buffer));
  if (message_patterns.empty()) {
    return std::make_optional(std::move(ss.split()));
  } else {
    return std::nullopt;
  }
}

std::optional<std::tuple<CipherState, CipherState>>
HandshakeState::read_message(std::vector<std::uint8_t> &message,
                             std::vector<std::uint8_t> &payload_buffer) {
  payload_buffer.clear();
  if (!message_patterns.empty()) {
    const auto &current_pattern = message_patterns.front();
    for (const auto &token : current_pattern) {
      using enum PatternToken;
      switch (token) {
      case E: {
        std::copy_n(std::make_move_iterator(message.begin()), 32, repk.begin());
        message.erase(message.begin(), message.begin() + 32);
        ss.mix_hash(repk);
      } break;
      case S: {
        std::vector<std::uint8_t> temp;
        if (ss.cs_has_key()) {
          temp.resize(32 + 16);
          std::copy_n(std::make_move_iterator(message.begin()), 32 + 16,
                      temp.begin());
          message.erase(message.begin(), message.begin() + 32 + 16);
        } else {
          temp.resize(32);
          std::copy_n(std::make_move_iterator(message.begin()), 32,
                      temp.begin());
          message.erase(message.begin(), message.begin() + 32);
        }
        ss.decrypt_and_hash(temp);
        std::ranges::fill(rspk, 0);
        std::ranges::move(temp, rspk.begin());
      } break;
      case Ee: {
        auto dhres = dh(esk, repk);
        ss.mix_key(dhres);
        crypto_wipe(dhres.data(), dhres.size());
      } break;
      case Es: {
        std::array<std::uint8_t, 32> key;
        if (initiator) {
          key = dh(esk, rspk);
        } else {
          key = dh(ssk, repk);
        }
        ss.mix_key(key);
      } break;
      case Se: {
        std::array<std::uint8_t, 32> key;
        if (initiator) {
          key = dh(ssk, repk);
        } else {
          key = dh(esk, rspk);
        }
        ss.mix_key(key);
      } break;
      case Ss: {
        auto dhres = dh(ssk, rspk);
        ss.mix_key(dhres);
        crypto_wipe(dhres.data(), dhres.size());
      } break;
      }
    }
    message_patterns.pop_front();
  }
  ss.decrypt_and_hash(message);
  std::ranges::move(message, std::back_inserter(payload_buffer));
  if (message_patterns.empty()) {
    return std::make_optional(std::move(ss.split()));
  } else {
    return std::nullopt;
  }
}

std::array<std::uint8_t, 64> HandshakeState::get_handshake_hash() {
  return ss.get_handshake_hash();
}
} // namespace noise
