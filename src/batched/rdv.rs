use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use drop::async_trait;
use drop::crypto::key::exchange::PublicKey;

use snafu::Snafu;

/// Batch creation configuration enum.
#[derive(Copy, Clone, Debug)]
pub enum RdvConfig {
    /// Use a remote peer identified by `PublicKey` as `Batch` creator
    Remote {
        /// The remote peer to use as rendez vous point
        peer: PublicKey,
    },
    /// Create `Batch`es locally
    Local,
}

impl RdvConfig {
    /// The rendezvous point for this instance is local
    pub fn local() -> Self {
        Self::Local
    }

    /// The rendezvous point is a remote peer identified by its `PublicKey`
    pub fn remote(peer: PublicKey) -> Self {
        Self::Remote { peer }
    }
}

#[async_trait]
/// A trait encapsulating a policy for picking Rendezvous point for batch construction
pub trait RdvPolicy: Send + Sync + FromStr {
    /// Pick a new rendezvous node
    async fn pick(&self) -> RdvConfig;
}

/// A `RdvPolicy` that always uses the same batcher node
pub struct Fixed {
    config: RdvConfig,
}

impl Fixed {
    /// Create a new `Fixed` `RdvPolicy` with local batch creation
    pub fn new_local() -> Self {
        Self {
            config: RdvConfig::Local,
        }
    }

    /// Create a new `Fixed` `RdvPolicy` with a specifid remote peer
    pub fn new_remote(peer: PublicKey) -> Self {
        Self {
            config: RdvConfig::Remote { peer },
        }
    }
}

#[async_trait]
impl RdvPolicy for Fixed {
    async fn pick(&self) -> RdvConfig {
        self.config
    }
}

impl FromStr for Fixed {
    type Err = FixedParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!("parse {} into a fixed policy", s)
    }
}

#[derive(Debug, Snafu)]
/// Parse error encountered when parsing a `Fixed` `RdvPolicy`
pub struct FixedParseError(FixedParseErrorInner);

#[derive(Debug, Snafu)]
enum FixedParseErrorInner {
    #[snafu(display("badly formatted policy"))]
    BadFmt,
    #[snafu(display("error parsing key"))]
    KeyParse,
}

/// A `RdvPolicy` that uses round-robin to decide which batcher to use
pub struct RoundRobin {
    last: AtomicUsize,
    batchers: Vec<PublicKey>,
}

impl RoundRobin {
    /// Create a  new `RoundRobin` `RdvPolicy` using a specified set of batching nodes
    pub fn new<I: IntoIterator<Item = PublicKey>>(batchers: I) -> Self {
        Self {
            last: AtomicUsize::new(0),
            batchers: batchers.into_iter().collect(),
        }
    }
}

#[async_trait]
impl RdvPolicy for RoundRobin {
    async fn pick(&self) -> RdvConfig {
        let peer = self
            .batchers
            .get(self.last.fetch_add(1, Ordering::AcqRel) % self.batchers.len())
            .unwrap();

        RdvConfig::Remote { peer: *peer }
    }
}

impl FromStr for RoundRobin {
    type Err = FixedParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!("parse  {} into a round robin policy", s)
    }
}
