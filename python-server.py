from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.handshakepatterns.interactive.NN import NNHandshakePattern
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2b import Blake2bHash
import dissononce, logging
from websockets.sync.server import serve, ServerConnection


def handler(conn):
    print("Instantiating initiator")
    initiator = HandshakeState(
        SymmetricState(CipherState(ChaChaPolyCipher()), Blake2bHash()), X25519DH()
    )
    print("Initializing NN with no prologue")
    initiator.initialize(NNHandshakePattern(), True, b"")
    print("Executing phase 1...")
    message_buffer = bytearray()
    initiator.write_message(b"", message_buffer)
    print(f"Client should see: {message_buffer.hex()}")
    conn.send(message_buffer)
    resp = conn.recv()
    ciphers = initiator.read_message(resp, message_buffer)
    if ciphers is None:
        print("Handshake failed")
        conn.close()
        return
    print("Handshake successful")
    print (f"Handshake state hash should be {initiator.symmetricstate.get_handshake_hash().hex()}")
    conn.close()


print("Waiting for responder...")
dissononce.logger.setLevel(logging.DEBUG)
with serve(handler, "localhost", 4000) as s:
    s.serve_forever()
