#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, deny(broken_intra_doc_links))]

//! Implementation of a probabilistic broadcast algorithm using Erdös-Rényi
//! gossip on top of the `drop` crate. <br />
//!
//! This crate provides an implementation of the [`Murmur`] algorithm using batching and bittorrent-like distribution of
//! batches. [`Batch`] creation involves payload collecting node (rendezvous nodes) that are reponsible for collating all
//! payloads into a [`Batch`] before disseminating the [`Batch`] throughout the network.
//!
//! Different rendez vous policy are supported using the [`RdvPolicy`] trait.
//!
//! See examples directory for some examples of how to use this in your own project
//!
//! [`Murmur`]: self::Murmur
//! [`Batch`]: self::Batch
//! [`RdvPolicy`]: self::RdvPolicy

/// Type for sequence numbers of a `Block`
pub type Sequence = u32;

mod config;
pub use config::{MurmurConfig, MurmurConfigBuilder};

#[cfg(feature = "system")]
mod system;
#[cfg(feature = "system")]
pub use system::*;
