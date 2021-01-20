#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, deny(broken_intra_doc_links))]

//! Implementation of a probabilistic broadcast algorithm using Erdös-Rényi
//! gossip on top of the `drop` crate. <br />
//! This crate contains two version of the `Murmur` algorithm, a classic `Murmur`
//! able to broadcast or receive a single message per instance and a `BatchedMurmur`
//! which provides batching and multishot broadcasting and receiving.
//! See `drop` documentation for more details on how to use `Murmur`.

/// Implementation of the classic murmur, without batching and other optimisations
pub mod classic;

/// Implemenation of murmur that provides batching, latency and other optimisations
///
pub mod batched;
