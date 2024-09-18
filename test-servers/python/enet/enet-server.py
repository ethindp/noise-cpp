from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.NN import NNHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2b import Blake2bHash
import enet
from enet import *
import logging, dissononce

dissononce.logger.setLevel(logging.DEBUG)

sessions = {}
hs_states = {}
peers = []
host = enet.Host(enet.Address(b"0.0.0.0", 4000), 4095, 255, 0, 0)
print("Listening on 0.0.0.0:4000")
while True:
    event = host.service(0)
    buf = bytearray()  # Temporary buffer
    match event.type:
        case enet.EVENT_TYPE_CONNECT:
            peers.append(event.peer)
            print("Peer connected")
            hs_states[event.peer] = HandshakeState(
                SymmetricState(CipherState(ChaChaPolyCipher()), Blake2bHash()),
                X25519DH(),
            )  # Describes the protocol to use, which is derived from these params. In this case, we use the ChaCha20Poly1305 cipher, the Blake2B hash function, and the Curve25519 key exchange algorithm.
            hs_states[event.peer].initialize(
                NNHandshakePattern(), True, b""
            )  # Handshake pattern to use, initiator or responder, and any prologue data (we don't have any)
            # The first step of the NN handshake is to transmit our ephemeral public key.
            hs_states[event.peer].write_message(b"", buf)  # Write our message into buf
            print(f"Sending: {buf.hex()}")
            event.peer.send(1, Packet(bytes(buf), PACKET_FLAG_RELIABLE))
            host.flush()
        case enet.EVENT_TYPE_DISCONNECT:
            peers.remove(event.peer)
            if event.peer in hs_states:
                hs_states.pop(event.peer)
            elif event.peer in sessions:
                sessions.pop(event.peer)
            print("Peer disconnected")
        case enet.EVENT_TYPE_RECEIVE:
            if event.peer in hs_states:  # We're still doing the handshake
                # The client has just sent it's ephemeral public key. Read it into the state to complete the handshake
                buf = bytearray()
                sessions[event.peer] = hs_states[event.peer].read_message(
                    event.peer.data, buf
                )
                print(f"Received: {buf.hex()}")
                # Verify that we've completed the handshake on our side
                if sessions[event.peer] is not None:
                    # We do not need the handshake state anymore
                    hs_states.pop(event.peer)
                    print("Handshake completed")
                else:
                    print("Handshake failure!")
                    hs_states.pop(event.peer)
                    event.peer.disconnect_now()
            elif event.peer in sessions:
                cipher_send, cipher_recv = sessions[event.peer]
                # We are fully encrypted!
                # The first cipher is a CipherState object which is used for transmitting data.
                # The second cipher is a CipherState object used for decrypting data.
                # Decrypt the message that was received
                # The first parameter is any associated data (AD) for the AEAD cipher.
                # The specification mandates that a zero-length ad be used.
                buf = cipher_recv.decrypt_with_ad(b"", event.peer.data)
                print(f"Received from client: {buf.hex()}")
            else:
                print(f"Internal error! Received: {event.peer.data.hex()}")
        case enet.EVENT_TYPE_NONE:
            continue
