# noise-cpp
An implementation of the Noise protocol framework for C++20

## Building
This project doesn't require you to build a thing. Simple drop the following files into your project's source code directories and go:

* `monocypher.{c|h}`
* `monocypher-ed25519.{c|h}`
* `rng_get_bytes.{c|h}`
* `noise.{cpp|h}`

The sole dependency is `magic_enum`, which is used for static reflection of pattern names.

There is a meson.build file, but all it does is build the test application (a client server that is just for verifying that the library works).

## Usage

To use this library, you need only include `noise.h`. Then, initialize a `noise::HandshakePattern` object. (Although the header exposes low-level objects, they are purely internal and shouldn't normally be used, except for `CipherState`.) Then, once you've allocated a `HandshakeState` object:

* call `initialize(...)` with the pattern you wish to use (in the `HandshakePattern` enum), whether this side is an initiator or not, and any prologue data you wish to use as a part of negotiation; and then
* Use `read_message`/`write_message` to complete the handshake!

Note that `initialize` also may take the static/ephemeral keys for both the initiator and responder as parameters after the prologue data; for the initiator, this is a full key pair, and for the responder (remote side) this is solely the public key. However, these should only be used if the pattern your using either requires them or you wish to use mutual authentication (and even then, leave the ephemeral keys as `std::nullopt` because setting them risks complete compromise of the session). Pre-shared keys are NOT supported at this time.

The library exposes a helper function, `generate_keypair`, which does exactly what it's name would suggest. Although this function is also used internally by Noise, it is exposed if you either don't want to mess around with OS-level interfaces or you don't want to pull in yet more code just to do this for you in a safe and secure manner.

As you call `read|write_message`, you will get back an optional value. When empty, the handshake is still in progress. Execute the handshake until this is no longer `std::nullopt`. When this occurs, the option is full of a `std::tuple` of `CipherState`s. The first is for sending, and the second is for reception, if the initiator, or vice-versa for the responder.

## License

This code is licensed in the public domain. Attribution is of course appreciated and always encouraged, but definitely not a prerequisite in any form.

## Contributing

PRs are always welcome. I've no doubt that this library could use significant improvement. I'm happy to review any PRs, but if your PR is a significant change (i.e., completely replacing the hash/crypto routines), please open a discussion first.

