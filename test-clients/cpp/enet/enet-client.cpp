#include "noise.h"
#include "readerwriterqueue.h"
#include <algorithm>
#include <atomic>
#include <cassert>
#include <enet/enet.h>
#include <exception>
#include <fmt/core.h>
#include <iostream>
#include <iterator>
#include <ranges>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <variant>
#include <vector>

static moodycamel::ReaderWriterQueue<
    std::variant<std::string, std::vector<std::uint8_t>>>
    BUFS;
static std::atomic_flag QUIT, CONNECTED;
static ENetHost *HOST = nullptr;
static ENetPeer *PEER = nullptr;
static std::exception_ptr EXCPTR = nullptr;

void run_loop();

int main() {
  QUIT.clear();
  CONNECTED.clear();
  try {
    if (enet_initialize() < 0) {
      fmt::println("Enet initialization failure");
      return 1;
    }
    ENetAddress addr;
    std::string text_addr;
    fmt::print("Enter IP address to connect to: ");
    while ((std::cin >> text_addr)) {
      if (enet_address_set_host_ip(&addr, text_addr.data()) < 0) {
        if (enet_address_set_host(&addr, text_addr.data()) < 0) {
          fmt::println("Error: invalid IP address or host name");
          continue;
        }
        break;
      }
      break;
    }
    addr.port = 4000;
    HOST = enet_host_create(nullptr, 4095, 255, 0, 0);
    if (!HOST) {
      fmt::println("Host creation failed");
      return 1;
    }
    PEER = enet_host_connect(HOST, &addr, 255, 0);
    if (!PEER) {
      fmt::println("Peer allocation failure");
      enet_host_destroy(HOST);
      return 1;
    }
    fmt::println("Connecting, and waiting for commands, enter quit to exit");
    auto t = std::thread(run_loop);
    while (!CONNECTED.test())
      ;
    std::string in;
    while ((std::cin >> in)) {
      if (in == "quit") {
        QUIT.test_and_set();
        t.join();
        enet_host_destroy(HOST);
        HOST = nullptr;
        enet_deinitialize();
        return 1;
      }
      if (EXCPTR) {
        enet_host_destroy(HOST);
        HOST = nullptr;
        std::rethrow_exception(EXCPTR);
      }
      if (!in.empty()) {
        BUFS.enqueue(in);
      }
    }
    enet_deinitialize();
    return 0;
  } catch (std::exception &ex) {
    std::cerr << fmt::format("Networking thread terminated with exception: {}",
                             ex.what());
    enet_deinitialize();
    return 1;
  }
}

void run_loop() {
  noise::HandshakeState *hs =
      new noise::HandshakeState; // We manually allocate this so we have exact
                                 // control over when it's cleaned up
  try {
    hs->initialize(noise::HandshakePattern::NN, false);
    std::tuple<noise::CipherState, noise::CipherState> ciphers;
    std::vector<std::uint8_t> read_buf;
    read_buf.reserve(65535);
    std::vector<std::uint8_t> write_buf, tmp, null_payload;
    while (!QUIT.test()) {
      ENetEvent event{};
      if (auto res = enet_host_service(HOST, &event, 0); res < 0) {
        throw std::runtime_error("Socket error");
      } else {
        if (res == 0) {
          assert(event.type == ENET_EVENT_TYPE_NONE);
        }
      }
      switch (event.type) {
      case ENET_EVENT_TYPE_NONE: {
        std::variant<std::string, std::vector<std::uint8_t>> data_to_send;
        if (!BUFS.try_dequeue(data_to_send)) {
          continue;
        }
        if (hs) {
          fmt::println("Processing handshake messages");
          if (std::holds_alternative<std::vector<std::uint8_t>>(data_to_send)) {
            auto buf = std::get<std::vector<std::uint8_t>>(data_to_send);
            fmt::println("Message has size {}", buf.size());
            auto packet = enet_packet_create(buf.data(), buf.size(),
                                             ENET_PACKET_FLAG_RELIABLE);
            fmt::println("Sending written HS packet, size {}",
                         packet->dataLength);
            if (enet_peer_send(PEER, 1, packet) < 0) {
              enet_packet_destroy(packet);
              fmt::println("Could not transmit data");
            }
            enet_host_flush(HOST);
            continue;
          }
          BUFS.enqueue(data_to_send);
          continue;
        }
        auto buf = std::get<std::string>(data_to_send);
        tmp.clear();
        for (const auto &chr : buf) {
          tmp.push_back(static_cast<std::uint8_t>(chr));
        }
        auto [send_cipher, receive_cipher] = ciphers;
        std::vector<std::uint8_t> null_ad;
        send_cipher.encrypt_with_ad(null_ad, tmp);
        auto packet = enet_packet_create(tmp.data(), tmp.size(),
                                         ENET_PACKET_FLAG_RELIABLE |
                                             ENET_PACKET_FLAG_NO_ALLOCATE);
        if (enet_peer_send(PEER, 1, packet) < 0) {
          enet_packet_destroy(packet);
          fmt::println("Could not transmit data");
        }
      } break;
      case ENET_EVENT_TYPE_CONNECT:
        fmt::println("Connection established");
        break;
      case ENET_EVENT_TYPE_DISCONNECT: {
        fmt::println("Disconnected, code {}", event.data);
        if (hs) {
          delete hs;
        }
        QUIT.test_and_set();
        return;
      } break;
      case ENET_EVENT_TYPE_RECEIVE: {
        if (hs) { // still negotiating
          fmt::println("Reading HS message, size {}", event.packet->dataLength);
          for (auto i = 0; i < event.packet->dataLength; ++i) {
            read_buf.push_back(event.packet->data[i]);
          }
          fmt::println("Calling read message");
          if (hs->read_message(read_buf, tmp)) {
            throw std::runtime_error("Handshake failed");
          }
          fmt::println("Clearing tmp");
          tmp.clear();
          fmt::println("Clearing read_buf");
          read_buf.clear();
          if (const auto res = hs->write_message(null_payload, write_buf);
              res) {
            null_payload.clear();
            if (hs) {
              delete hs;
            }
            ciphers = *res;
            fmt::println("Handshake completed");
            fmt::println("Queueing write buffer of size {}", write_buf.size());
            BUFS.enqueue(write_buf);
            CONNECTED.test_and_set();
            continue;
          } else {
            throw std::runtime_error("Handshake failed!");
          }
        }
        read_buf.clear();
        for (auto i = 0; i < event.packet->dataLength; ++i) {
          read_buf.push_back(event.packet->data[i]);
        }
        auto [send_cipher, recv_cipher] = ciphers;
        std::vector<std::uint8_t> null_ad;
        recv_cipher.decrypt_with_ad(null_ad, read_buf);
        std::string received_data;
        received_data.reserve(read_buf.size());
        for (const auto &byte : read_buf) {
          received_data += static_cast<char>(byte);
        }
        fmt::println("Received: {}", received_data);
      } break;
      }
    }
  } catch (std::exception &ex) {
    if (hs) {
      delete hs;
    }
    EXCPTR = std::current_exception();
  }
}
