use std::time::Duration;

use derive_builder::Builder;

use serde::{Deserialize, Serialize};

const DEFAULT_SPONGE_THRESHOLD: &str = "8194";
const DEFAULT_CHANNEL_CAP: &str = "64";
const DEFAULT_BLOCK_SIZE: &str = "256";
const DEFAULT_BATCH_DELAY: &str = "200";
const DEFAULT_TIMEOUT: &str = "3";

#[cfg_attr(feature = "structopt", derive(structopt::StructOpt))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Builder)]
/// Configuration information for `BatchedMurmur`
pub struct BatchedMurmurConfig {
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_CHANNEL_CAP))]
    #[doc = "Channel buffer size"]
    #[builder(default = DEFAULT_CHANNEL_CAP)]
    /// Channel capacity
    pub channel_cap: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_SPONGE_THRESHOLD))]
    #[doc = "Sponge capacity (this will be the size of locally created batches)"]
    #[builder(default = DEFAULT_SPONGE_THRESHOLD)]
    /// Threshold for beginning batch spread in the network
    pub sponge_threshold: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_BLOCK_SIZE))]
    #[doc = "Size of individual blocks inside locally created batches"]
    #[builder(default = DEFAULT_BLOCK_SIZE)]
    /// Block size
    pub block_size: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_BATCH_DELAY))]
    #[doc = "The maximum amount of time to wait before starting batch propagation in milliseconds"]
    #[builder(default = DEFAULT_BATCH_DELAY)]
    /// Default delay to start spreading batch in msecs
    pub batch_delay: u64,

    #[cfg_attr(feature = "structopt", structopt(long, short))]
    #[doc = "Expected size of the gossip set when sampling"]
    pub gossip_size: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_TIMEOUT))]
    #[doc = "Request timeout in seconds"]
    #[builder(default = DEFAULT_TIMEOUT)]
    /// Timeout duration in seconds
    pub timeout: u64,
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

    /// Get the batch delay
    pub fn batch_delay(&self) -> Duration {
        Duration::from_millis(self.batch_delay)
    }

    /// Get the timeout duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout)
    }
}

impl Default for BatchedMurmurConfig {
    fn default() -> Self {
        Self {
            channel_cap: DEFAULT_CHANNEL_CAP.parse().unwrap(),
            sponge_threshold: DEFAULT_SPONGE_THRESHOLD.parse().unwrap(),
            block_size: DEFAULT_BLOCK_SIZE.parse().unwrap(),
            batch_delay: DEFAULT_BATCH_DELAY.parse().unwrap(),
            timeout: DEFAULT_TIMEOUT.parse().unwrap(),
            gossip_size: 10,
        }
    }
}
