#![deny(missing_docs)]

//! Implementation of a probabilistic broadcast algorithm using Erdös-Rényi
//! gossip on top of the `drop` crate. <br />
//! See `drop` documentation for more details on how to use `Murmur`.

/// Implementation of the classic murmur, without batching and other optimisations
pub mod classic;

/// Implemenation of mrumur that provides batching, latency and other optimisations
pub mod batched;
