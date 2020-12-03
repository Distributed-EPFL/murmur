#![deny(missing_docs)]

//! Implementation of a probabilistic broadcast algorithm using Erdös-Rényi
//! gossip on top of the `drop` crate. <br />
//! See `drop` documentation for more details on how to use `Murmur`.


mod classic;
pub use classic::{Murmur, MurmurError, MurmurHandle, MurmurMessage, MurmurProcessingError};
