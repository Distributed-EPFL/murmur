use std::time::Duration;

use derive_builder::Builder;

use serde::{Deserialize, Serialize};

const DEFAULT_EXPIRATION_MINUTE: &str = "5";
const DEFAULT_SPONGE_THRESHOLD: &str = "1024";
const DEFAULT_CHANNEL_CAP: &str = "64";
const DEFAULT_BLOCK_SIZE: &str = "256";
const DEFAULT_BATCH_DELAY: &str = "200";
const DEFAULT_TIMEOUT: &str = "3";

#[cfg_attr(feature = "structopt", derive(structopt::StructOpt))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Builder)]
/// Configuration information for [`Murmur`]
///
/// [`Murmur`]: super::Murmur
pub struct MurmurConfig {
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_CHANNEL_CAP))]
    #[builder(default = DEFAULT_CHANNEL_CAP)]
    /// Channel capacity
    pub channel_cap: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_SPONGE_THRESHOLD))]
    #[builder(default = DEFAULT_SPONGE_THRESHOLD)]
    /// Threshold for beginning batch spread in the network
    pub sponge_threshold: usize,

    #[cfg_attr(feature = "structopt", structopt(long, default_value = DEFAULT_BLOCK_SIZE))]
    #[builder(default = DEFAULT_BLOCK_SIZE)]
    /// Size of individual blocks inside locally created batches
    pub block_size: usize,

    #[cfg_attr(feature = "structopt", structopt(long, default_value = DEFAULT_BATCH_DELAY))]
    #[builder(default = DEFAULT_BATCH_DELAY)]
    /// Default delay before starting to spread a batch in msecs
    pub batch_delay: u64,

    #[cfg_attr(feature = "structopt", structopt(long))]
    #[doc = "Expected size of the gossip set when sampling"]
    pub murmur_gossip_size: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_TIMEOUT))]
    #[builder(default = DEFAULT_TIMEOUT)]
    /// Timeout duration in seconds
    pub timeout: u64,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = DEFAULT_EXPIRATION_MINUTE))]
    #[builder(default = DEFAULT_EXPIRATION_MINUTE)]
    /// Delay for batch expiration in minutes
    pub batch_expiration: u64,
}

impl MurmurConfig {
    /// Get the batch delay as a Duration
    pub fn batch_delay(&self) -> Duration {
        Duration::from_millis(self.batch_delay)
    }

    /// Get the delay to expunge completed batch from memory
    pub fn batch_expiration(&self) -> Duration {
        Duration::from_secs(self.batch_expiration * 60)
    }

    /// Get the timeout duration as a Duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout)
    }
}

impl Default for MurmurConfig {
    fn default() -> Self {
        Self {
            batch_expiration: DEFAULT_EXPIRATION_MINUTE.parse().unwrap(),
            channel_cap: DEFAULT_CHANNEL_CAP.parse().unwrap(),
            sponge_threshold: DEFAULT_SPONGE_THRESHOLD.parse().unwrap(),
            block_size: DEFAULT_BLOCK_SIZE.parse().unwrap(),
            batch_delay: DEFAULT_BATCH_DELAY.parse().unwrap(),
            timeout: DEFAULT_TIMEOUT.parse().unwrap(),
            murmur_gossip_size: 10,
        }
    }
}
