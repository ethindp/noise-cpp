#define ENET_IMPLEMENTATION
#include "noise.h"
#include "enet.h"
#include "concurrentqueue.h"
#include <fmt/core.h>
#include <atomic>
#include <iostream>
#include <string>
#include <variant>
#include <vector>
#include <thread>
#include <stop_token>
#include <exception>
#include <algorithm>
#include <ranges>
#include <iterator>
#include <tuple>
#include <cstdint>

static moodycamel::ConcurrentQueue<std::vector<std::uint8_t>> DATA_QUEUE;
static moodycamel::ConcurrentQueue<std::string> INBOUND_DATA_QUEUE;
static std::atomic_flag CONNECTED, BEGIN_HANDLING_INPUT;
static ENetHost* HOST;
static ENetPeer* PEER;
static std::exception_ptr EXCPTR;

void run_loop(std::stop_token stoken);

int main() {
CONNECTED.clear();
std::jthread thread(run_loop);
enet_initialize();
HOST = enet_host_create(nullptr, ENET_PROTOCOL_MAXIMUM_PEER_ID, ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT, 0, 0);
if (!HOST) {
fmt::println("ENet host could not be initialized");
return 1;
}
std::string addr_str;
ENetAddress addr;
fmt::print("Enter IP address or host name: ");
while ((std::cin >> addr_str)) {
if (enet_address_set_host_ip_new(&addr, addr_str.data()) < 0 || enet_address_set_host_new(&addr, addr_str.data()) < 0) {
fmt::println("Invalid IP address or host name, please try again.");
fmt::print("Enter IP address or host name: ");
continue;
}
break;
}
addr.port = 4000;
PEER = enet_host_connect(HOST, &addr, 255, 0);
if (!PEER) {
fmt::println("Could not connect to {}!", addr_str);
return 1;
}
CONNECTED.test_and_set();
CONNECTED.notify_all();
BEGIN_HANDLING_INPUT.wait(false);
fmt::println("Connected!");
while (true) {
if (EXCPTR) {
try {
std::rethrow_exception(EXCPTR);
} catch (std::exception& ex) {
fmt::println("Error: {}", ex.what());
enet_host_destroy(HOST);
enet_deinitialize();
return 1;
}
}
std::string data;
if (INBOUND_DATA_QUEUE.try_dequeue(data)) {
fmt::println("Received: {}", data);
}
std::string in;
if ((std::cin >> in)) {
if (in == "quit") {
fmt::println("Exiting");
thread.request_stop();
thread.join();
enet_host_destroy(HOST);
enet_deinitialize();
return 1;
}
std::vector<std::uint8_t> inbytes;
std::transform(in.begin(), in.end(), std::back_inserter(inbytes), [](const auto chr) { return static_cast<std::uint8_t>(chr); });
DATA_QUEUE.enqueue(inbytes);
}
}
return 0;
}

void run_loop(std::stop_token stoken) {
CONNECTED.wait(false);
try {
noise::HandshakeState* hs = new noise::HandshakeState;
hs->initialize(noise::HandshakePattern::NN, false);
std::tuple<noise::CipherState, noise::CipherState> ciphers;
// The below code is a bit of a mess. I'm sure there's an even more gorgeous/elegant solution.
while (!stoken.stop_requested()) {
ENetEvent evt;
if (enet_host_service(HOST, &evt, 0) < 0) {
throw std::runtime_error("Host could not be serviced");
}
switch (evt.type) {
case ENET_EVENT_TYPE_NONE: {
std::vector<std::uint8_t> data;
if (!DATA_QUEUE.try_dequeue(data)) {
if (hs) {
if (!hs->is_handshake_finished()) {
if (hs->is_my_turn()) {
hs->write_message(data);
DATA_QUEUE.enqueue(data);
}
}
}
continue;
}
if (data.empty()) {
continue;
}
ENetPacket* packet;
if (hs) {
packet = enet_packet_create(data.data(), data.size(), ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_NO_ALLOCATE);
} else {
auto [send_cipher, _] = ciphers;
send_cipher.encrypt_with_ad(data);
packet = enet_packet_create(data.data(), data.size(), ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_NO_ALLOCATE);
}
if (!packet) {
throw std::runtime_error("Could not create packet!");
}
if (enet_peer_send(PEER, 0, packet) < 0) {
enet_packet_destroy(packet);
throw std::runtime_error("Could not transmit packet!");
}
}
break;
case ENET_EVENT_TYPE_CONNECT: {
BEGIN_HANDLING_INPUT.test_and_set();
BEGIN_HANDLING_INPUT.notify_all();
}
break;
case ENET_EVENT_TYPE_DISCONNECT: {
fmt::println("Disconnected from server");
return;
}
break;
case ENET_EVENT_TYPE_RECEIVE: {
if (hs) {
if (!hs->is_handshake_finished()) {
if (!hs->is_my_turn()) {
std::vector<std::uint8_t> data_buf{evt.packet->data, evt.packet->data + evt.packet->dataLength};
std::vector<std::uint8_t> read_buf;
hs->read_message(data_buf, read_buf);
continue;
}
} else {
ciphers = hs->finalize();
delete hs;
}
}
auto [_, recv_cipher] = ciphers;
std::vector<std::uint8_t> data_buf{evt.packet->data, evt.packet->data + evt.packet->dataLength};
recv_cipher.decrypt_with_ad(data_buf);
std::string res;
res.resize(data_buf.size());
std::transform(data_buf.begin(), data_buf.end(), res.begin(), [](const auto b) { return static_cast<char>(b); });
INBOUND_DATA_QUEUE.enqueue(res);
}
break;
case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT: {
fmt::println("Disconnect timeout received");
return;
}
break;
}
}
} catch (std::exception&) {
EXCPTR = std::current_exception();
}
}

