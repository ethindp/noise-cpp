use message_io::network::{NetEvent, Transport};
use message_io::node::{self};
use snow::Builder;

fn main() {
    let (handler, listener) = node::split::<()>();
    handler
        .network()
        .listen(Transport::FramedTcp, "0.0.0.0:3042")
        .unwrap();
    handler
        .network()
        .listen(Transport::Udp, "0.0.0.0:3043")
        .unwrap();
    handler
        .network()
        .listen(Transport::Ws, "0.0.0.0:4000")
        .unwrap();
    println!("Waiting for responder on ports 3042, 3043, and 4000...");
    let (mut read_buf, mut first_msg) = ([0u8; 1024], [0u8; 1024]);
    let mut initiator = Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2b".parse().unwrap())
        .build_initiator()
        .unwrap();
    listener.for_each(move |event| match event.network() {
        NetEvent::Connected(_, _) => unreachable!(),
        NetEvent::Accepted(endpoint, _listener) => {
            println!("Executing phase 1...");
            let _ = initiator.write_message(&[], &mut first_msg).unwrap();
            handler.network().send(endpoint, &first_msg);
        }
        NetEvent::Message(endpoint, data) => {
            println!("Completing handshake...");
            initiator.read_message(&data, &mut read_buf).unwrap();
            println!(
                "Final handshake state: {}",
                hex::encode(initiator.get_handshake_hash())
            );
            println!("Done");
            handler.network().remove(endpoint.resource_id());
        }
        NetEvent::Disconnected(_endpoint) => println!("Client disconnected"),
    });
}
