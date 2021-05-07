use std::time::Duration;

use derive_builder::Builder;

use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "structopt", derive(structopt::StructOpt))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Builder)]
/// Configuration information for [`Murmur`]
///
/// [`Murmur`]: super::Murmur
pub struct MurmurConfig {
    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "64"))]
    #[builder(default = "64")]
    /// Channel capacity
    pub channel_cap: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "1024"))]
    #[builder(default = "1024")]
    /// Threshold for beginning batch spread in the network
    pub sponge_threshold: usize,

    #[cfg_attr(feature = "structopt", structopt(long, default_value = "256"))]
    #[builder(default = "256")]
    /// Size of individual blocks inside locally created batches
    pub block_size: usize,

    #[cfg_attr(feature = "structopt", structopt(long, default_value = "200"))]
    #[builder(default = "200")]
    /// Default delay before starting to spread a batch in msecs
    pub batch_delay: u64,

    #[cfg_attr(feature = "structopt", structopt(long))]
    #[doc = "Expected size of the gossip set when sampling"]
    pub murmur_gossip_size: usize,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "1"))]
    #[builder(default = "1")]
    /// Timeout duration in seconds
    pub timeout: u64,

    #[cfg_attr(feature = "structopt", structopt(long, short, default_value = "5"))]
    #[builder(default = "5")]
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
        MurmurConfigBuilder::default()
            .murmur_gossip_size(10)
            .build()
            .unwrap()
    }
}
