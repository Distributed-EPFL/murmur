use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::iter::{self, FromIterator};

use drop::crypto::hash::Digest;
use drop::crypto::sign::{self, KeyPair, Signature, Signer, VerifyError};
use drop::system::{message, Message};

use serde::{Deserialize, Serialize};

pub(crate) type Sequence = u32;

#[message]
#[derive(Copy)]
/// A structure that uniquely identifies a `Block`
pub struct BlockId {
    digest: Digest,
    sequence: Sequence,
}

impl BlockId {
    pub fn new(digest: Digest, sequence: Sequence) -> Self {
        Self { digest, sequence }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn sequence(&self) -> Sequence {
        self.sequence
    }
}

impl PartialOrd for BlockId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.sequence.partial_cmp(&other.sequence)
    }
}

impl Ord for BlockId {
    fn cmp(&self, other: &Self) -> Ordering {
        // FIXME: once drop has `Ord` `Digest`
        self.partial_cmp(other).unwrap()
    }
}

/// Information about a `Batch`
#[message]
#[derive(Copy)]
pub struct BatchInfo {
    size: Sequence,
    digest: Digest,
}

impl BatchInfo {
    /// Create a new `BatchInfo` from a size and a digest
    pub fn new(size: Sequence, digest: Digest) -> Self {
        Self { size, digest }
    }

    /// Get the sequence of this `Block` inside its `Batch`
    pub fn sequence(&self) -> Sequence {
        self.size
    }

    /// Get the size of the associated `Batch`
    pub fn size(&self) -> usize {
        self.size as usize
    }

    /// Get the `Batch` `Digest`
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Display for BatchInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "batch {}", self.digest)
    }
}

#[message]
/// A batch of blocks that is being broadcasted
pub struct Batch<M: Message> {
    info: BatchInfo,
    #[serde(bound(deserialize = "M: Message"))]
    blocks: BTreeMap<Sequence, Block<M>>,
}

impl<M: Message> Batch<M> {
    pub(crate) fn new<I: IntoIterator<Item = Block<M>>>(info: BatchInfo, blocks: I) -> Self {
        Self {
            info,
            blocks: blocks
                .into_iter()
                .enumerate()
                .map(|(i, b)| (i as u32, b))
                .collect(),
        }
    }

    /// Get the `BatchInfo` from this `Batch`
    pub fn info(&self) -> &BatchInfo {
        &self.info
    }

    /// Acess the blocks of this `Batch`
    pub fn blocks(&self) -> impl Iterator<Item = &Block<M>> {
        self.blocks.iter().map(|(_, b)| b)
    }

    /// Get the length of this `Batch`
    pub fn len(&self) -> Sequence {
        self.blocks
            .iter()
            .map(|(_, b)| b)
            .fold(0, |acc, x| acc + x.len())
    }

    /// Check if this `Batch` is empty
    pub fn is_empty(&self) -> bool {
        !self.blocks.values().any(|b| b.len() > 0)
    }

    /// Convert this `Batch` into an `Iterator` of its `Block`s
    pub fn into_blocks(self) -> impl Iterator<Item = Block<M>> {
        self.blocks.into_iter().map(|(_, v)| v)
    }
}

impl<M: Message> std::ops::Index<Sequence> for Batch<M> {
    type Output = Payload<M>;

    fn index(&self, sequence: Sequence) -> &Self::Output {
        let mut len = 0;

        for block in self.blocks.iter().map(|(_, b)| b) {
            len += block.len();

            if len > sequence {
                return &block[sequence - len];
            }
        }

        unreachable!("index ouf of bounds: idx {}, len {}", sequence, len)
    }
}

impl<M: Message + 'static> IntoIterator for Batch<M> {
    type Item = Payload<M>;

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        let init: Box<dyn Iterator<Item = Payload<M>>> = Box::new(iter::empty());

        self.blocks
            .into_iter()
            .map(|(_, b)| b)
            .fold(init, |acc, curr| Box::new(acc.chain(curr)))
    }
}

impl<M> FromIterator<Block<M>> for Batch<M>
where
    M: Message,
{
    fn from_iter<I>(i: I) -> Self
    where
        I: IntoIterator<Item = Block<M>>,
    {
        use drop::crypto::hash;

        let blocks: Vec<_> = i.into_iter().collect();
        let len = blocks.iter().fold(0, |acc, b| acc + b.len());
        let digest = hash(&blocks).expect("hashing failed");
        let info = BatchInfo::new(len, digest);

        Self::new(info, blocks)
    }
}

#[message]
/// A `Block` is a set of messages that are part of the same `Batch`
pub struct Block<M: Message> {
    sequence: Sequence,
    #[serde(bound(deserialize = "M: Message"))]
    payloads: Vec<Payload<M>>,
}

impl<M: Message> Block<M> {
    pub fn new<I: IntoIterator<Item = Payload<M>>>(sequence: Sequence, payloads: I) -> Self {
        Self {
            sequence,
            payloads: payloads.into_iter().collect(),
        }
    }

    /// Sequence number of the `Block` inside the `Batch` it belongs to
    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Verify all `Payload`s in this `Block`. This either returns `Ok` if all payloads are correct,
    /// or the first `Err` encountered while verifying payloads.
    pub fn verify(&self, keypair: &KeyPair) -> Result<(), VerifyError> {
        self.payloads
            .iter()
            .find_map(|p| p.verify(keypair).err())
            .map(Err)
            .unwrap_or(Ok(()))
    }

    /// Returns the number of payloads in this `Block`
    pub fn len(&self) -> Sequence {
        self.payloads.len() as u32
    }
}

impl<M: Message> PartialOrd for Block<M> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<M: Message> Ord for Block<M> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sequence.cmp(&other.sequence)
    }
}

impl<M: Message> IntoIterator for Block<M> {
    type Item = Payload<M>;

    type IntoIter = std::vec::IntoIter<Payload<M>>;

    fn into_iter(self) -> Self::IntoIter {
        self.payloads.into_iter()
    }
}

impl<M: Message> std::ops::Index<Sequence> for Block<M> {
    type Output = Payload<M>;

    fn index(&self, seq: Sequence) -> &Self::Output {
        &self.payloads[seq as usize]
    }
}

#[message]
/// An individual message inside of a `Batch`
pub struct Payload<M> {
    sender: sign::PublicKey,
    sequence: Sequence,
    #[serde(bound(deserialize = "M: Message"))]
    payload: M,
    signature: Signature,
}

impl<M> Payload<M> {
    pub(crate) fn new(
        sender: sign::PublicKey,
        sequence: Sequence,
        payload: M,
        signature: Signature,
    ) -> Self {
        Self {
            sender,
            sequence,
            payload,
            signature,
        }
    }

    /// Get the `Signature` for this `Payload`
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Get the sequence number of this `Payload`
    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Get the actual content of this `Payload`
    pub fn payload(&self) -> &M {
        &self.payload
    }
}

impl<M: Message> Payload<M> {
    /// Verify the `Signature` of this `Payload`
    pub fn verify(&self, keypair: &KeyPair) -> Result<(), VerifyError> {
        Signer::new(keypair.clone()).verify(&self.signature, &self.sender, &self.payload)
    }
}

pub struct Sponge<M> {
    payloads: Vec<Payload<M>>,
}

impl<M> Sponge<M>
where
    M: Message,
{
    pub fn new() -> Self {
        Self {
            payloads: Vec::new(),
        }
    }

    pub fn insert(&mut self, payload: Payload<M>) {
        self.payloads.push(payload);
    }

    /// Returns the length of the `Sponge`
    pub fn len(&self) -> usize {
        self.payloads.len()
    }

    /// Create a `Batch` by emptying the `Payload`s in this `Sponge`
    /// Panics:
    /// Panics if block_size is 0
    pub fn drain_to_batch(&mut self, block_size: usize) -> Batch<M> {
        std::mem::take(&mut self.payloads)
            .chunks(block_size)
            .enumerate()
            .map(|(seq, payloads)| Block::new(seq as Sequence, payloads.iter().cloned()))
            .collect()
    }
}

impl<M: Message> Default for Sponge<M> {
    fn default() -> Self {
        Self::new()
    }
}