use std::time::Duration;

use derive_builder::Builder;

use serde::{Deserialize, Serialize};

const DEFAULT_SPONGE_THRESHOLD: &str = "8194";
const DEFAULT_CHANNEL_CAP: &str = "64";
const DEFAULT_BLOCK_SIZE: &str = "256";
const DEFAULT_BATCH_DELAY: &str = "200";
const DEFAULT_TIMEOUT: &str = "3";

#[builder(setter(into))]
#[cfg_attr(feature = "structopt", derive(structopt::StructOpt))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Builder)]
/// Configuration information for `BatchedMurmur`
pub struct BatchedMurmurConfig {
    #[builder(default = DEFAULT_CHANNEL_CAP)]
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_CHANNEL_CAP))]
    #[doc = "channel buffer size"]
    /// Channel capacity
    channel_cap: usize,

    #[builder(default = DEFAULT_SPONGE_THRESHOLD)]
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_SPONGE_THRESHOLD))]
    #[doc = "sponge capacity (this will be the size of locally created batches)"]
    /// Threshold for beginning batch spread in the network
    sponge_threshold: usize,

    #[builder(default = DEFAULT_BLOCK_SIZE)]
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_BLOCK_SIZE))]
    #[doc = "size of individual blocks inside locally created batches"]
    /// Block size
    block_size: usize,

    #[builder(default = DEFAULT_BATCH_DELAY)]
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_BATCH_DELAY))]
    #[doc = "the maximum amount of time to wait before starting batch propagation"]
    /// Default delay to start spreading batch in msecs
    batch_delay: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short))]
    #[doc = "expected size  of the gossip set when sampling"]
    gossip_size: usize,

    #[builder(default = DEFAULT_TIMEOUT)]
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_TIMEOUT))]
    #[doc = "request timeout in seconds"]
    /// Timeout duration in seconds
    timeout: usize,
}

impl BatchedMurmurConfig {
    /// Get the channel capacity from this configuration
    pub fn channel_cap(&self) -> usize {
        self.channel_cap
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
            channel_cap: 64,
            sponge_threshold: 8194,
            block_size: 256,
            batch_delay: 200,
            gossip_size: 10,
            timeout: 3,
        }
    }
}
