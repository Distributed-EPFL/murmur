use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::mem;
use std::ops::DerefMut;

use super::{Batch, BatchInfo, Block, Sequence};

use drop::crypto::hash::{hash, HashError};
use drop::system::Message;

use snafu::{ensure, Backtrace, ResultExt, Snafu};

use tokio::sync::{RwLock, RwLockMappedWriteGuard, RwLockReadGuard, RwLockWriteGuard};

use tracing::{debug, trace};

/// Error returned by the `BatchState` manager
#[derive(Debug, Snafu)]
pub enum BlockError {
    #[snafu(display("detected a block conflict"))]
    Conflict,
    #[snafu(display("missing blocks in batch"))]
    Missing,
    #[snafu(display("invalid batch hash"))]
    BadHash,
    #[snafu(display("unable to hash blocks: {}", source))]
    HashFail { source: HashError },
    #[snafu(display("batch is not complete"))]
    NotReady,
    #[snafu(display("block sequence is out of bounds"))]
    OutOfBounds,
    #[snafu(display("block is already complete"))]
    Completed { backtrace: Backtrace },
}

impl BlockError {
    /// Check whether it is worth continuing with this `BatchState`
    pub fn valid(&self) -> bool {
        !matches!(self, Self::BadHash | Self::HashFail { .. })
    }
}

/// State of a `Batch`
#[derive(Debug)]
pub enum State<M: Message> {
    Pending(BTreeMap<Sequence, Block<M>>),

    Complete {
        blocks: BTreeMap<Sequence, Block<M>>,
    },
}

/// Manager for the state of an incoming `Batch`
pub struct BatchState<M: Message> {
    info: BatchInfo,
    state: RwLock<State<M>>,
}

impl<M: Message + 'static> BatchState<M> {
    /// Create a new empty `BatchState`
    pub fn new(info: BatchInfo) -> Self {
        Self {
            info,
            state: Default::default(),
        }
    }

    /// Get the information of this `Batch`
    pub fn info(&self) -> &BatchInfo {
        &self.info
    }

    /// Register a new `Block` for this `Batch`. This also removes any pending block requests
    /// for the inserted `Block` if the insert is successful. <br />
    /// It should be checked before inserting that the `Block` is valid.
    pub async fn insert(&self, block: Block<M>) -> Result<(), BlockError> {
        ensure!(block.sequence() < self.info.sequence(), OutOfBounds);

        match *self.state.write().await {
            State::Pending(ref mut blocks) => {
                debug!("trying insert for valid block {}", block.sequence());

                match blocks.entry(block.sequence()) {
                    Entry::Occupied(e) => {
                        ensure!(e.get() == &block, Conflict);
                        Ok(())
                    }
                    Entry::Vacant(e) => {
                        e.insert(block);
                        Ok(())
                    }
                }
            }
            _ => Completed.fail(),
        }
    }

    /// Get a `Block` according to its `Sequence`
    pub async fn get_sequence(&self, sequence: Sequence) -> Option<Block<M>> {
        self.blocks().await.get(&sequence).map(Clone::clone)
    }

    /// Returns a mutable reference to the map of blocks.
    /// This returns an error if the batch is already complete
    async fn blocks_mut(
        &self,
    ) -> Result<RwLockMappedWriteGuard<'_, BTreeMap<Sequence, Block<M>>>, BlockError> {
        RwLockWriteGuard::try_map(self.state.write().await, |state| match state {
            State::Pending(ref mut blocks) => Some(blocks),
            _ => None,
        })
        .map_err(|_| snafu::NoneError)
        .context(Completed)
    }

    /// Returns the map of blocks of this `BatchState`
    pub async fn blocks(&self) -> RwLockReadGuard<'_, BTreeMap<Sequence, Block<M>>> {
        RwLockReadGuard::map(self.state.read().await, |state| match state {
            State::Pending(blocks) => blocks,
            State::Complete { blocks } => blocks,
        })
    }

    /// Convert this `BatchState` in a complete `Batch` if it is possible in the current state.
    pub async fn complete(&self) -> Result<(), BlockError> {
        let blocks = {
            let mut blocks = self.blocks_mut().await?;
            let have_blocks = blocks.keys().count() == self.info.size();

            ensure!(have_blocks, Missing);

            mem::take(blocks.deref_mut())
        };

        trace!("all blocks received for batch {}", self.info);

        let digest = hash(&blocks).context(HashFail)?;

        ensure!(&digest == self.info.digest(), BadHash);

        trace!("correct hash for batch {}", self.info);

        *self.state.write().await = State::Complete { blocks };

        Ok(())
    }

    /// Turn this `BatchState` in an immutable `Batch`
    pub async fn to_batch(&self) -> Result<Batch<M>, BlockError> {
        match *self.state.write().await {
            State::Complete { ref mut blocks } => {
                let blocks = std::mem::take(blocks);
                let batch = (self.info, blocks).into();

                Ok(batch)
            }
            State::Pending { .. } => NotReady.fail(),
        }
    }
}

impl<M> fmt::Debug for BatchState<M>
where
    M: Message,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.info)
    }
}

impl<M> fmt::Display for BatchState<M>
where
    M: Message,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} with {} blocks",
            self.info.digest(),
            self.info.sequence()
        )
    }
}

impl<M> PartialEq for BatchState<M>
where
    M: Message,
{
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info
    }
}

impl<M: Message> Default for State<M> {
    fn default() -> Self {
        Self::Pending(Default::default())
    }
}

#[cfg(any(test, feature = "test"))]
pub mod test {
    use super::super::{Batch, Payload};
    use super::*;

    use drop::crypto::sign::Signer;

    #[cfg(any(feature = "test", test))]
    pub use utils::*;

    #[cfg(any(feature = "test", test))]
    mod utils {
        use super::*;

        fn generate_block(seq: Sequence, size: usize) -> Block<u32> {
            let payloads = (0..size).map(|x| {
                let mut signer = Signer::random();
                let idx = x as u32;
                let signature = signer.sign(&idx).expect("sign failed");

                Payload::new(*signer.public(), idx, idx, signature)
            });

            Block::new(seq, payloads)
        }

        /// Generate a `Batch` for testing purposes
        pub fn generate_batch(size: usize) -> Batch<u32> {
            let blocks: BTreeMap<_, _> = (0..size as Sequence)
                .map(|x| (x, generate_block(x, size)))
                .collect();
            let digest = hash(&blocks).expect("hash failed");
            let size = size as u32;
            let info = BatchInfo::new(size, digest);

            Batch::new(info, blocks.into_iter().map(|(_, block)| block))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn correct_block_registration() {
            static SIZE: usize = 50;

            let batch = generate_batch(SIZE);
            let state = BatchState::new(*batch.info());

            for block in batch.blocks() {
                state.insert(block.clone()).await.expect("insert failed");
            }

            state
                .complete()
                .await
                .expect("batch not registered as complete");

            let expected: Vec<_> = batch.blocks().collect();
            let guard = state.blocks().await;

            for i in 0..SIZE {
                let actual = &guard[&(i as u32)];
                let expected = expected[i];

                assert_eq!(actual, expected);
            }
        }
    }
}
