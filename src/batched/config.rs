use std::time::Duration;

use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "structopt", derive(structopt::StructOpt))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Configuration information for `BatchedMurmur`
pub struct BatchedMurmurConfig {
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "8194"))]
    /// Threshold for beginning batch spread in the network
    sponge_threshold: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "256"))]
    /// Block size
    block_size: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "200"))]
    /// Default delay to start spreading batch in msecs
    batch_delay: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "10"))]
    gossip_size: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "3"))]
    /// Timeout duration in seconds
    timeout: usize,
}

impl BatchedMurmurConfig {
    /// Create a new `BatchedMurmurConfig` using specified values for each parameter.
    pub fn new(
        gossip_size: usize,
        sponge_threshold: usize,
        block_size: usize,
        batch_delay: usize,
        timeout: usize,
    ) -> Self {
        Self {
            gossip_size,
            sponge_threshold,
            block_size,
            batch_delay,
            timeout,
        }
    }

    /// Get the expected size of the gossip set of peers
    pub fn gossip_size(&self) -> usize {
        self.gossip_size
    }

    /// Get the sponge threshold
    pub fn sponge_threshold(&self) -> usize {
        self.sponge_threshold
    }

    /// Get the block size
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Get the batch delay property
    pub fn batch_delay(&self) -> usize {
        self.batch_delay
    }

    /// Get the timeout duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout as u64)
    }
}

impl Default for BatchedMurmurConfig {
    fn default() -> Self {
        Self {
            sponge_threshold: 8194,
            block_size: 256,
            batch_delay: 200,
            gossip_size: 10,
            timeout: 3,
        }
    }
}
