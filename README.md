# noise-cpp
An implementation of the Noise protocol framework for C++20

## Building
This project doesn't require you to build a thing. Simply drop the following files into your project's source code directories and go:

* `monocypher.{c|h}`
* `monocypher-ed25519.{c|h}`
* `rng_get_bytes.{c|h}`
* `noise.{cpp|h}`

There is a `meson.build` file, but all it does is build the examples.

## Usage

To use this library, you need only include `noise.h`. Then, initialize a `noise::HandshakeState` object. (Although the header exposes low-level objects, they are purely internal and shouldn't normally be used, except for `CipherState`.) Then, once you've allocated a `HandshakeState` object:

* create a `noise::HandshakeStateConfiguration` object which contains the configuration needed for this instance (i.e., keys, initiator configuration, etc.);
* Call `HandshakeState::initialize(config_object)`, which will set up all internal state and perform nearly all checks; and
* Use `read_message`/`write_message` to complete the handshake!

Note that the configuration object takes the static/ephemeral keys for both the initiator and responder as fields after the prologue data; for the initiator, this is a full key pair, and for the responder (remote side) this is solely the public key. However, these should only be used if the pattern your using either requires them or you wish to use mutual authentication (and even then, leave the ephemeral keys as `std::nullopt` because setting them risks complete compromise of the session). If you need any PSKs, set them in the psks` field.

Warnings:

1. If you select a pattern which requires PSKs but do not specify any, the handshake state machine will fail upon reaching a `psk` token.
2. The number of processed PSKs is limited to the number of `psk` tokens in the handshake pattern. If you pass in more PSKs than there are `psk` tokens, those excess PSKs will not be processed.

The library exposes a helper function, `generate_keypair`, which does exactly what it's name would suggest. Although this function is also used internally by Noise, it is exposed if you either don't want to mess around with OS-level interfaces or you don't want to pull in yet more code just to do this for you in a safe and secure manner.

To complete the handshake, you generally loop until `is_handshake_finished()` is true. In this loop:

* if `is_my_turn()`, this is a signal that it is your turn to write/read messages. You should perform the write/read in the appropriate order and send the resulting message over the transport you are using, if any.
* Otherwise, the remote end has sent a message. Read the payload with `read_message` and then do a `write_message` call to send back the next message in the handshake.

In code, this handshake generally follows the template:

```cpp
    while (!initiator.is_handshake_finished()) {
      if (initiator.is_my_turn()) {
        initiator.write_message(sendbuf);
        send_message_over_appropriate_transport(sendbuf);
      } else {
        read_message_from_transport(recvbuf);
        initiator.read_message(recvbuf, output_payload_buffer);
      }
    }
```

Here:

* `sendbuf` is the buffer to which data is written before it is sent over some transport.
* `recvbuf` is the buffer into which some transport dumps a raw data payload. The transport MUST NOT decrypt or otherwise tamper with the payload.
* `output_payload_buffer` is the buffer in which the decrypted message is to be written.

The library uses pass-by-reference all over the place. Although this generally causes code to be less beautiful, it is necessary for cryptographic security to ensure that you don't need to handle clearing buffers of sensitive information. You can run an extra wipe pass if you like, but the library will do this automatically for you.

If you wish to rekey, this can be done on a `CipherState` object by calling `CipherState::rekey`. As per the Noise specification, when and how this is done is up to the application and is not automatically done by this library.

## License

This code is licensed in the public domain. Attribution is of course appreciated and always encouraged, but definitely not a prerequisite in any form.

## Contributing

PRs are always welcome. I've no doubt that this library could use significant improvement. I'm happy to review any PRs, but if your PR is a significant change (i.e., completely replacing the hash/crypto routines), please open a discussion first.

If you wish to add a new handshake pattern, the general process is as follows:

1. Add (to the end) the name of the handshake pattern to the `noise::HandshakePattern` enumeration.
2. If your pattern requires any new tokens, add them to the `PatternToken` enumeration. This should be avoided unless you know what your doing.
3. Edit `noise::handshake_pattern_to_string` and add, at the end of the switch statement and before the `default` case, the pattern you've added and it's string representation. For example, this is usually a `1:1` translation, i.e., `NN -> "NN"`, but this is still required.
4. Update the `initialize` function in `HandshakeState` and add, at the end of the very large switch statement but before the `default` case, the patterns that this new handshake pattern requires (pre-messages and message patterns).
5. If you have added new pattern tokens, update `read_message` and `write_message` to process them.

Adding new tokens is strongly discouraged unless there is no way to express them some other way. The same generally goes for handshake patterns themselves, particularly if they have not been professionally audited/vetted. Custom handshake patterns are not currently supported and may never be supported, as it is difficult to programatically verify all of the requirements for handshake validity.