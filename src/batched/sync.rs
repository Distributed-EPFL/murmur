use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::mem;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Instant;

use super::{Batch, BatchInfo, Block, BlockId, Sequence};

use drop::crypto::hash::{hash, HashError};
use drop::crypto::key::exchange::PublicKey;
use drop::crypto::sign::{KeyPair, VerifyError};
use drop::system::Message;

use snafu::{ensure, Backtrace, ResultExt, Snafu};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

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
    #[snafu(display("invalid block signature: {}", source))]
    BadSignature { source: VerifyError },
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
        !matches!(self, Self::BadHash | Self::HashFail { .. } | Self::BadSignature { .. })
    }
}

/// State of a `Batch`
#[derive(Debug)]
pub enum State<M: Message> {
    Pending(
        BTreeMap<Sequence, Block<M>>,
        BTreeMap<Sequence, (Instant, PublicKey)>,
    ),

    Complete {
        blocks: BTreeMap<Sequence, Block<M>>,
    },
}

/// Manager for the state of an incoming `Batch`
pub struct BatchState<M: Message> {
    info: BatchInfo,
    keypair: KeyPair,
    state: RwLock<State<M>>,
}

impl<M: Message + 'static> BatchState<M> {
    /// Create a new `BatchState` manager
    pub fn new(info: BatchInfo, keypair: KeyPair) -> Self {
        Self {
            info,
            keypair,
            state: Default::default(),
        }
    }

    /// Create a new complete `BatchState` from a full `Batch`
    pub fn new_completed(batch: Batch<M>, keypair: KeyPair) -> Self {
        let info = *batch.info();

        Self {
            info,
            keypair,
            state: RwLock::new(State::Complete {
                blocks: batch
                    .into_blocks()
                    .enumerate()
                    .map(|(seq, block)| (seq as Sequence, block))
                    .collect(),
            }),
        }
    }

    /// Get the information of this `Batch`
    pub fn info(&self) -> BatchInfo {
        self.info
    }

    /// Register a new `Block` for this `Batch`. This also removes any pending block requests
    /// for the inserted `Block` if the insert is successful.
    pub async fn insert(&self, block: Block<M>) -> Result<(), BlockError> {
        ensure!(block.sequence() < self.info.sequence(), OutOfBounds);

        block.verify(&self.keypair).context(BadSignature)?;

        match *self.state.write().await {
            State::Pending(ref mut blocks, ref mut pending) => {
                debug!("trying insert for valid block {}", block.sequence());

                match blocks.entry(block.sequence()) {
                    Entry::Occupied(e) => {
                        ensure!(e.get() == &block, Conflict);
                        Ok(())
                    }
                    Entry::Vacant(e) => {
                        pending.remove(&block.sequence());
                        e.insert(block);
                        Ok(())
                    }
                }
            }
            _ => Completed.fail(),
        }
    }

    /// Register a pending request for a new `Block` if necessary. This returns an error if this `Batch` is already
    /// complete, otherwise an `Ok(bool)` is returned the boolean indicating whether or not a request should be sent.
    pub async fn request(&self, sequence: Sequence, from: PublicKey) -> Result<bool, BlockError> {
        ensure!(sequence < self.info.sequence(), OutOfBounds);

        match *self.state.write().await {
            State::Pending(ref blocks, ref mut requests) => {
                if blocks.contains_key(&sequence) {
                    trace!(
                        "already have block {} in batch {}",
                        sequence,
                        self.info.digest()
                    );
                    return Completed.fail();
                }

                match requests.entry(sequence) {
                    Entry::Vacant(e) => {
                        e.insert((Instant::now(), from));
                        Ok(true)
                    }
                    Entry::Occupied(mut e) => {
                        if Instant::now().duration_since(e.get().0) >= super::DEFAULT_TIMEOUT {
                            debug!(
                                "detected timeout for block {} of batch {}",
                                sequence,
                                self.info.digest()
                            );
                            e.insert((Instant::now(), from));
                            Ok(true)
                        } else {
                            debug!(
                                "already pending request for block {} in batch {}",
                                sequence,
                                self.info.digest()
                            );
                            Ok(false)
                        }
                    }
                }
            }
            _ => Completed.fail(),
        }
    }

    /// Fetch a clone of the `Block` identified by some `BlockId`
    pub async fn get(&self, block: &BlockId) -> Option<Block<M>> {
        if self.info.digest() == block.digest() {
            self.get_sequence(block.sequence()).await
        } else {
            None
        }
    }

    /// Get a `Block` according to its `Sequence`
    pub async fn get_sequence(&self, sequence: Sequence) -> Option<Block<M>> {
        self.blocks().await.get(&sequence).map(Clone::clone)
    }

    /// Check if it is worth doing a deeper check for `Batch` completness
    pub async fn check(&self) -> Result<(), BlockError> {
        ensure!(self.blocks().await.len() == self.info.size(), NotReady);

        Ok(())
    }

    // /// Returns a mutable reference to the map of blocks.
    // /// This returns an error if the batch is already complete
    // async fn blocks_mut(
    //     &self,
    // ) -> Result<RwLockWriteGuard<'_, BTreeMap<Sequence, Block<M>>>, BlockError> {
    //     RwLockWriteGuard::try_map(self.state.write().await, |state| match state {
    //         State::Pending(ref mut blocks, _) => Some(blocks),
    //         _ => None,
    //     })
    //     .map_err(|_| snafu::NoneError)
    //     .context(Completed)
    // }

    async fn blocks_mut(&self) -> Result<BlockWriteGuard<'_, M>, BlockError> {
        use std::convert::TryInto;
        let state = self.state.write().await;

        Ok(state.try_into()?)
    }

    /// Returns the map of blocks of this `BatchState`
    pub async fn blocks(&self) -> RwLockReadGuard<'_, BTreeMap<Sequence, Block<M>>> {
        RwLockReadGuard::map(self.state.read().await, |state| match state {
            State::Pending(blocks, _) => blocks,
            State::Complete { blocks } => blocks,
        })
    }

    pub async fn available(&self) -> bool {
        matches!(*self.state.read().await, State::Complete{..})
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

/// Temporary wrapper until tokio allows mapping RwLockWriteGuard again
#[derive(Debug)]
pub struct BlockWriteGuard<'a, M>
where
    M: Message,
{
    lock: RwLockWriteGuard<'a, State<M>>,
}

impl<'a, M> std::ops::Deref for BlockWriteGuard<'a, M>
where
    M: Message,
{
    type Target = BTreeMap<Sequence, Block<M>>;

    fn deref(&self) -> &Self::Target {
        if let State::Pending(ref blocks, ..) = *self.lock {
            blocks
        } else {
            panic!("")
        }
    }
}

impl<'a, M> DerefMut for BlockWriteGuard<'a, M>
where
    M: Message,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        if let State::Pending(ref mut blocks, ..) = *self.lock {
            blocks
        } else {
            panic!("")
        }
    }
}

impl<'a, M> std::convert::TryFrom<RwLockWriteGuard<'a, State<M>>> for BlockWriteGuard<'a, M>
where
    M: Message,
{
    type Error = BlockError;

    fn try_from(lock: RwLockWriteGuard<'a, State<M>>) -> Result<Self, Self::Error> {
        if let State::Pending { .. } = *lock {
            Ok(Self { lock })
        } else {
            Completed.fail()
        }
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
        Self::Pending(Default::default(), Default::default())
    }
}

#[derive(Clone, Debug)]
/// Shared reference to a complete `Batch`
pub struct BatchRef<M>
where
    M: Message,
{
    state: Arc<BatchState<M>>,
}

impl<M> From<Arc<BatchState<M>>> for BatchRef<M>
where
    M: Message,
{
    fn from(state: Arc<BatchState<M>>) -> Self {
        Self { state }
    }
}

impl<M> std::ops::Deref for BatchRef<M>
where
    M: Message,
{
    type Target = BatchState<M>;

    fn deref(&self) -> &Self::Target {
        self.state.deref()
    }
}

impl<M> PartialEq for BatchRef<M>
where
    M: Message,
{
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info
    }
}

impl<M> Eq for BatchRef<M> where M: Message {}

#[cfg(any(test, feature = "test"))]
pub mod test {
    use super::super::{Batch, Payload};
    use super::*;

    use drop::crypto::sign::Signer;

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

    #[tokio::test]
    async fn correct_block_registration() {
        static SIZE: usize = 50;

        let batch = generate_batch(SIZE);
        let state = BatchState::new(*batch.info(), KeyPair::random());

        for block in batch.blocks() {
            state.insert(block.clone()).await.expect("insert failed");
        }

        state.check().await.expect("incorrect batch state");

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

    #[tokio::test]
    async fn pull_request_timeout() {
        static SIZE: usize = 10;

        use std::time::Duration;

        drop::test::init_logger();

        let batch = generate_batch(SIZE);
        let state = BatchState::new(*batch.info(), KeyPair::random());
        let key = *drop::crypto::key::exchange::KeyPair::random().public();

        state
            .insert(batch.blocks().next().unwrap().clone())
            .await
            .expect("failed first insert");
        state.request(1, key).await.expect("failed first request");

        tokio::time::sleep(super::super::DEFAULT_TIMEOUT + Duration::from_secs(1)).await;

        state.request(1, key).await.expect("timeout not registered");
    }

    #[tokio::test]
    async fn no_mut_complete_batch() {
        static SIZE: usize = 10;

        let batch = generate_batch(SIZE);
        let state = BatchState::new_completed(batch, KeyPair::random());

        state
            .blocks_mut()
            .await
            .expect_err("could edit blocks from a completed batch");
    }

    #[tokio::test]
    async fn completed_request_fails() {
        static SIZE: usize = 10;

        use drop::crypto::key::exchange::KeyPair;
        use drop::crypto::sign;

        let batch = generate_batch(SIZE);
        let state = BatchState::new_completed(batch, sign::KeyPair::random());

        state
            .request(0, *KeyPair::random().public())
            .await
            .expect_err("could request block for complete batch");
    }

    #[tokio::test]
    async fn fetch_block() {
        static SIZE: usize = 10;

        let batch = generate_batch(SIZE);
        let digest = *batch.info().digest();
        let state = BatchState::new_completed(batch, KeyPair::random());

        for seq in 0..(SIZE as Sequence) {
            state.get_sequence(seq).await.expect("block not found");
            state
                .get(&BlockId::new(digest, seq))
                .await
                .expect("block not found");
        }
    }
}
