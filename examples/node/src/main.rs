use std::net::{AddrParseError, SocketAddr};

use drop::crypto::key::exchange::{Exchanger, KeyPair, PublicKey};
use drop::crypto::sign;
use drop::crypto::ParseHexError;
use drop::net::{TcpConnector, TcpListener};
use drop::system::manager::{Handle, SystemManager};
use drop::system::sampler::AllSampler;
use drop::system::System;

use murmur::batched::{BatchedMurmur, BatchedMurmurConfig, Fixed};

use snafu::{ResultExt, Snafu};

use structopt::StructOpt;

const MESSAGE_COUNT: usize = 2000;

#[derive(Debug)]
struct PeerInfo(SocketAddr, PublicKey);

impl PeerInfo {
    fn to_tuple(self) -> (SocketAddr, PublicKey) {
        (self.0, self.1)
    }
}

impl std::str::FromStr for PeerInfo {
    type Err = PeerParseError;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let components = v.split("-").collect::<Vec<_>>();

        if components.len() < 2 {
            return Err(PeerParseError::Invalid);
        }

        let addr = components[0].parse().context(Addr)?;
        let key = PublicKey::from_str(components[1]).context(Key)?;

        Ok(Self(addr, key))
    }
}

#[derive(Debug, Snafu)]
enum PeerParseError {
    /// The socket address failed to parse correctly
    #[snafu(display("failed to parse address: {}", source))]
    Addr { source: AddrParseError },

    /// The public was not well-formed hex
    #[snafu(display("failed to parse public key: {}", source))]
    Key { source: ParseHexError },

    /// Format is invalid
    #[snafu(display("invalid peer specification"))]
    Invalid,
}

#[derive(Debug, StructOpt)]
/// Command line argument processing is delegated to the structopt cratev
struct NodeConfig {
    #[structopt(flatten)]
    murmur: BatchedMurmurConfig,

    #[structopt(short("-l"), long("--listen"))]
    /// Address to listen on for incoming connections
    listener_addr: SocketAddr,

    #[structopt(name = "peers")]
    /// List of peers to connect to at startup, format is "ip:port-publickey"
    peers: Vec<PeerInfo>,
}

#[tokio::main]
async fn main() {
    let config = NodeConfig::from_args();

    println!("{:?}", config);

    // We generate a random `KeyPair` in this example but it can also be serialized
    // and stored on-disk for resuming operations with the same identity
    let keypair = KeyPair::random();

    println!("local identity is {}", keypair.public());

    let exchanger = Exchanger::new(keypair);

    // here we establish initial connections as specified in command-line arguments
    let (addrs, keys): (Vec<_>, Vec<_>) = config.peers.into_iter().map(PeerInfo::to_tuple).unzip();
    let connector = TcpConnector::new(exchanger.clone());
    let mut system = System::new_with_connector(&connector, keys, addrs).await;

    // we also listen on localhost:2009 wih tcp to accept connections from new peers
    let listener = TcpListener::new(config.listener_addr, exchanger)
        .await
        .expect("failed to listen for incoming connections");

    // when adding a listener we get a stream that will produce errors encountered while accepting connections
    let _ = system.add_listener(listener).await;

    let manager = SystemManager::new(system);

    // we now create the murmur instance we will use to broadcast and receive messages  from the network and
    // set it up to use a local batching policy
    // note that murmur takes a different kind of cryptographic keys since those are only used to sign messages
    // and not to perform network communication
    let murmur = BatchedMurmur::new(sign::KeyPair::random(), Fixed::new_local(), config.murmur);

    // we choose to use a deterministic version of murmur by selecting a sampler that takes every known peer
    let sampler = AllSampler::default();

    // we now tell the system manager to start processing messages using murmur and get a handle allowing us to
    // interact with murmur
    let mut handle = manager.run(murmur, sampler).await;

    // now we start broadcasting all integers from 0 to 1999 on the network
    for i in 0..MESSAGE_COUNT {
        handle.broadcast(&i).await.expect("broadcasting failed");
    }

    // if the byzantine bounds hold in our current network we should eventually deliver every broadcasted message
    // split between different batches

    let mut delivered = 0;

    while delivered < MESSAGE_COUNT {
        let batch = handle.deliver().await.expect("delivering failed");

        batch
            .iter()
            .for_each(|msg| println!("delivered {} from {}", msg.payload(), msg.sender()));

        delivered += batch.len() as usize;
    }
}
