//! This module provides an optimized implementation of [`Murmur`] using batching and bittorrent-like distribution of
//! [`Batch`]es. Batch creation involves payload collecting node (rendezvous nodes) that are reponsible for collating all
//! payloads into a [`Batch`] before disseminating the [`Batch`] throughout the network.
//!
//! Different rendez vous policy are supported using the [`RdvPolicy`] trait.
//!
//! [`Murmur`]: crate::classic::Murmur
//! [`Batch`]: crate::batched::Batch
//! [`rdvPolicy`]: crate::batched::RdvPolicy

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::iter;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use drop::async_trait;
use drop::crypto::hash::Digest;
use drop::crypto::key::exchange::PublicKey;
use drop::crypto::sign::{KeyPair, SignError, Signer, VerifyError};
use drop::system::manager::Handle;
use drop::system::{message, Message, Processor, Sampler, Sender, SenderError};

use futures::future::OptionFuture;

use serde::{Deserialize, Serialize};

use snafu::{OptionExt, ResultExt, Snafu};

use tokio::sync::{mpsc, Mutex, RwLock};

use tracing::{debug, error, trace, warn};

/// Default buffering at `Batch` creation
pub static DEFAULT_SPONGE_THRESHOLD: usize = 8194 * 2;

/// Default size for blocks
pub static DEFAULT_BLOCK_SIZE: usize = 1024;

/// Default timeout for block re-request
pub static DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum number of retries for failed requests
pub static MAX_RETRIES: usize = 3;

/// Type for sequence numbers of a `Block`
pub type Sequence = u32;

mod rdv;
pub use rdv::*;

mod structs;
pub use structs::{Batch, BatchInfo, Payload};
pub(self) use structs::{Block, BlockId, Sponge};

mod sync;
#[cfg(any(feature = "test", test))]
pub use sync::test::*;
pub use sync::BatchRef;
use sync::BatchState;

#[derive(Debug, Snafu)]
/// Errors encountered by `BatchedMurmurHandle` when delivering or broadcasting
pub enum BatchError {
    #[snafu(display("instance has died"))]
    /// Channel used by instance is dead
    Channel,
    #[snafu(display("broadcast failed: {}", source))]
    /// Unable to broadcast message
    Broadcast {
        /// Underliying error cause
        source: SenderError,
    },
    #[snafu(display("message signing failed: {}", source))]
    /// Error signing mesage
    Sign {
        /// Underlying error cause
        source: SignError,
    },
}

#[derive(Debug, Snafu)]
/// Errors encountered when processing a message
pub enum BatchProcessingError {
    #[snafu(display("network error:{}", source))]
    /// Network error encountered
    Network {
        /// Error source
        source: drop::system::SenderError,
    },

    #[snafu(display("bad block from {}: {}", from, source))]
    /// Invalid block encountered
    InvalidBlock {
        /// Source of the bad block
        from: PublicKey,
        /// Reason why the block is invalid
        source: VerifyError,
    },

    #[snafu(display("request for batch {} that we don't know", digest))]
    /// Peer requested blocks from an unknown batch
    UnknownBatch {
        /// Hash of the unknown Batch
        digest: Digest,
    },

    #[snafu(display("processor not setup"))]
    /// The `Processor` wasn't initialized
    Setup,
}

#[derive(Eq)]
struct BlockProvider {
    public: PublicKey,
    latency: Duration,
}

impl PartialEq for BlockProvider {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

impl PartialOrd for BlockProvider {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockProvider {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.latency.cmp(&other.latency)
    }
}

#[message]
/// Messages exchanged by `BatchedMurmur`
pub enum BatchedMurmurMessage<M: Message> {
    /// Peer announces a `Batch` and whether it has it
    Announce(BatchInfo, bool),
    /// Advertise the view we have of a `Batch`
    Advertise(BatchInfo, Vec<Sequence>),
    /// Peer requests that we send them a `Block` from some `Batch`
    Pull(BlockId),
    #[serde(bound(deserialize = "M: Message"))]
    /// Peer sends a `Block` belonging to some `Batch`
    Transmit(BatchInfo, Sequence, Block<M>),
    /// Peer wants to subscribe to our updates
    Subscribe,
    /// Put a message in a `Batch` using a Rendezvous node
    #[serde(bound(deserialize = "M: Message"))]
    Collect(Payload<M>),
}

/// A version of Murmur that provides multiple optimisation over `Murmur` such as
/// latency selection of peers, batching and bittorrent-like block distribution.
/// It also supports multi-shot broadcasting, e.g. one sender can send multiple block
/// using the same instance of `BatchedMurmur` as well as receive multiple messages using
/// the same instance
pub struct BatchedMurmur<M: Message, R: RdvPolicy> {
    keypair: KeyPair,
    batches: RwLock<HashMap<Digest, State<M>>>,

    rendezvous: Arc<R>,
    sponge: Mutex<Sponge<M>>,
    sponge_threshold: usize,

    delivery: Mutex<Option<mpsc::Sender<Arc<Batch<M>>>>>,

    gossip: RwLock<HashSet<PublicKey>>,
}

impl<M, R> BatchedMurmur<M, R>
where
    M: Message + 'static,
    R: RdvPolicy,
{
    /// Create a new `BatchedMurmur`
    pub fn new(keypair: KeyPair, rendezvous: R) -> Self {
        Self {
            keypair,
            sponge_threshold: DEFAULT_SPONGE_THRESHOLD,
            rendezvous: Arc::new(rendezvous),
            batches: Default::default(),
            gossip: Default::default(),
            sponge: Default::default(),
            delivery: Default::default(),
        }
    }

    /// Announces the specified `Batch` to gossip peers
    async fn announce<S: Sender<BatchedMurmurMessage<M>> + 'static>(
        &self,
        info: BatchInfo,
        available: bool,
        sender: Arc<S>,
    ) -> Result<(), BatchProcessingError> {
        let message = Arc::new(BatchedMurmurMessage::Announce(info, available));

        debug!(
            "announcing new batch {} of size {} to peers",
            info.digest(),
            info.size()
        );

        sender
            .send_many(message, self.gossip.read().await.iter())
            .await
            .context(Network)
    }

    async fn is_delivered(&self, digest: &Digest) -> bool {
        self.batches
            .read()
            .await
            .get(digest)
            .map(|x| x.is_complete())
            .unwrap_or(false)
    }

    /// Get a `Block` from a specified `Batch`. The `Block` can be either a
    /// completed and delivered `Block` or a `Block` in a pending `Batch`
    async fn get_block(&self, id: &BlockId) -> Option<Block<M>> {
        OptionFuture::from(
            self.batches
                .read()
                .await
                .get(id.digest())
                .map(|x| x.get_block(id.sequence())),
        )
        .await
        .flatten()
    }

    /// Insert a block into this `Incomplete` batch. Returns `true` if the `Batch` can still be completed after
    /// even if this `Block` is incorrect somehow
    async fn insert_block(&self, id: BlockId, block: Block<M>) -> bool {
        if let Some(manager) = self.pending_by_digest(id.digest()).await {
            manager
                .insert(block)
                .await
                .map_or_else(|e| e.valid(), |_| true)
        } else {
            false
        }
    }

    async fn try_deliver(
        &self,
        digest: &Digest,
    ) -> Result<Option<Arc<Batch<M>>>, BatchProcessingError> {
        let mut guard = self.batches.write().await;

        match guard.entry(*digest) {
            Entry::Vacant(_) => Ok(None),
            Entry::Occupied(mut e) => {
                if let Some(batch) = e.get_mut().ready().await {
                    Ok(Some(batch))
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn pending_by_digest(&self, digest: &Digest) -> Option<Arc<BatchState<M>>> {
        self.batches
            .read()
            .await
            .get(digest)
            .map(|x| x.to_pending())
            .flatten()
    }

    async fn batchinfo(&self, blockid: &BlockId) -> Option<BatchInfo> {
        self.batches
            .read()
            .await
            .get(blockid.digest())
            .map(|batch| *batch.info())
    }

    async fn get_manager_or_insert(&self, info: BatchInfo) -> Option<Arc<BatchState<M>>> {
        debug!("updating batch state for {}", info.digest());

        self.batches
            .write()
            .await
            .entry(*info.digest())
            .or_insert_with(|| {
                debug!("new batch {} registered", info.digest());
                Arc::new(BatchState::new(info, self.keypair.clone())).into()
            })
            .to_pending()
    }

    async fn insert_batch(&self, batch: Batch<M>) {
        self.batches
            .write()
            .await
            .entry(*batch.info().digest())
            .or_insert_with(|| Arc::new(batch).into());
    }

    async fn advertise<S>(
        &self,
        info: BatchInfo,
        sequence: Sequence,
        sender: Arc<S>,
    ) -> Result<(), BatchProcessingError>
    where
        S: Sender<BatchedMurmurMessage<M>>,
    {
        let message = BatchedMurmurMessage::Advertise(info, vec![sequence]);

        debug!(
            "advertising block {} from {} to peers",
            sequence,
            info.digest()
        );

        sender
            .send_many(Arc::new(message), self.gossip.read().await.iter())
            .await
            .context(Network)
    }

    async fn pull_missing_blocks<I, S>(
        &self,
        info: BatchInfo,
        available: I,
        from: PublicKey,
        sender: Arc<S>,
    ) -> Result<(), BatchProcessingError>
    where
        I: Iterator<Item = Sequence>,
        S: Sender<BatchedMurmurMessage<M>>,
    {
        if let Some(manager) = self.get_manager_or_insert(info).await {
            // TODO: handle timeout and failure to retrieve a `Block`

            debug!(
                "pulling missing blocks for batch {} from {}",
                info.digest(),
                from
            );

            for sequence in available {
                if let Ok(true) = manager.request(sequence, from).await {
                    debug!(
                        "outgoing request for block {} of batch {} from {}",
                        sequence,
                        info.digest(),
                        from
                    );

                    let blockid = BlockId::new(*info.digest(), sequence);
                    let message = BatchedMurmurMessage::Pull(blockid);
                    sender
                        .send(Arc::new(message), &from)
                        .await
                        .context(Network)?;
                } else {
                    debug!(
                        "already pending request for block {} of batch {}",
                        sequence,
                        info.digest()
                    );
                }
            }
        } else {
            debug!(
                "no need to  pull blocks for complete batch {}",
                info.digest()
            );
        }

        Ok(())
    }
}

#[async_trait]
impl<M, S, R> Processor<BatchedMurmurMessage<M>, M, Arc<Batch<M>>, S> for BatchedMurmur<M, R>
where
    M: Message + 'static,
    R: RdvPolicy,
    S: Sender<BatchedMurmurMessage<M>> + 'static,
{
    type Handle = BatchedHandle<M, Arc<Batch<M>>, S, R>;

    type Error = BatchProcessingError;

    async fn process(
        self: Arc<Self>,
        message: Arc<BatchedMurmurMessage<M>>,
        from: PublicKey,
        sender: Arc<S>,
    ) -> Result<(), Self::Error> {
        match message.deref() {
            BatchedMurmurMessage::Announce(info, has) => {
                if *has {
                    self.pull_missing_blocks(*info, (0..info.sequence()), from, sender)
                        .await?;
                } else {
                    self.pull_missing_blocks(*info, iter::empty(), from, sender)
                        .await?;
                }
            }

            BatchedMurmurMessage::Advertise(info, blocks) => {
                trace!(
                    "{} advertising {} blocks from batch {}",
                    from,
                    blocks.len(),
                    info
                );

                self.pull_missing_blocks(*info, blocks.iter().copied(), from, sender)
                    .await?;
            }

            BatchedMurmurMessage::Pull(blockid) => {
                trace!(
                    "request for block {}  for batch {} from {}",
                    blockid.sequence(),
                    blockid.digest(),
                    from
                );

                if let Some(block) = self.get_block(blockid).await {
                    debug!(
                        "sending block {} of batch {} to {}",
                        blockid.sequence(),
                        blockid.digest(),
                        from
                    );
                    let info = self.batchinfo(&blockid).await.context(UnknownBatch {
                        digest: *blockid.digest(),
                    })?;

                    let message = BatchedMurmurMessage::Transmit(info, blockid.sequence(), block);

                    sender
                        .send(Arc::new(message), &from)
                        .await
                        .context(Network)?;
                } else {
                    warn!(
                        "peer requested block {} from batch {} that we don't have yet",
                        blockid.sequence(),
                        blockid.digest()
                    );
                }
            }

            BatchedMurmurMessage::Transmit(info, sequence, block) => {
                if self.is_delivered(info.digest()).await {
                    return Ok(());
                }

                block.verify(&self.keypair).context(InvalidBlock { from })?;

                debug!(
                    "received valid block {} for batch {} from {}",
                    sequence,
                    info.digest(),
                    from
                );

                let blockid = BlockId::new(*info.digest(), *sequence);

                if self.insert_block(blockid, block.clone()).await {
                    trace!(
                        "registered new block {} for {}",
                        blockid.sequence(),
                        info.digest()
                    );

                    if let Some(batch) = self.try_deliver(info.digest()).await? {
                        debug!("batch {} is complete", info.digest());
                        self.announce(*info, true, sender).await?;

                        if let Err(e) = self
                            .delivery
                            .lock()
                            .await
                            .as_mut()
                            .context(Setup)?
                            .send(batch)
                            .await
                        {
                            error!("handle was dropped early: {}", e);
                        }
                    } else {
                        self.advertise(*info, *sequence, sender.clone()).await?;
                    }
                }
            }

            BatchedMurmurMessage::Collect(payload) => {
                payload
                    .verify(&self.keypair)
                    .context(InvalidBlock { from })?;

                let mut sponge = self.sponge.lock().await;

                debug!(
                    "collecting payload from {}, batch completion {}/{}",
                    from,
                    sponge.len(),
                    self.sponge_threshold
                );

                sponge.insert(payload.clone());

                if sponge.len() >= self.sponge_threshold {
                    trace!("sponge threshold reached, creating batch...");

                    let batch = sponge.drain_to_batch(DEFAULT_BLOCK_SIZE);
                    let info = *batch.info();

                    self.insert_batch(batch).await;

                    self.announce(info, true, sender).await?;
                }
            }

            BatchedMurmurMessage::Subscribe => {
                if self.gossip.write().await.insert(from) {
                    // FIXME: pending issue https://github.com/rust-lang/rust/issues/64552
                    //     stream::iter(self.batches.read().await.values())
                    //         .filter_map(|batch| async move {
                    //             if batch.is_complete().await {
                    //                 Some(batch)
                    //             } else {
                    //                 None
                    //             }
                    //         })
                    //         .zip(stream::repeat(sender))
                    //         .for_each_concurrent(None, |(batch, sender)| async move {
                    //             let message = BatchedMurmurMessage::Announce(batch.info(), true);

                    //             if let Err(e) = sender.send(Arc::new(message), &from).await {
                    //                 error!("error announcing to {}: {}", from, e);
                    //             }
                    //         })
                    //         .await;

                    debug!("new subscription from {}", from);

                    for batch in self.batches.read().await.values() {
                        debug!(
                            "announcing batch {} after subscription from: {}",
                            batch.info().digest(),
                            from
                        );
                        let available = batch.available();
                        let message = BatchedMurmurMessage::Announce(*batch.info(), available);

                        sender
                            .send(Arc::new(message), &from)
                            .await
                            .context(Network)?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn output<SA: Sampler>(&mut self, sampler: Arc<SA>, sender: Arc<S>) -> Self::Handle {
        let keys = sender.keys().await;
        let sample = sampler
            .sample(keys.iter().copied(), 0)
            .await
            .expect("sampling failed");

        debug!(
            "initial sampling finished with {} remote peers",
            sample.len()
        );

        self.gossip.write().await.extend(sample);

        sender
            .clone()
            .send_many(
                Arc::new(BatchedMurmurMessage::Subscribe),
                self.gossip.read().await.iter(),
            )
            .await
            .expect("subscription failed");

        for batch in self.batches.read().await.values() {
            debug!("initial announcement of {}", batch);

            if let Err(e) = self
                .announce(*batch.info(), batch.available(), sender.clone())
                .await
            {
                error!("failed announcing batch:{}", e);
            }
        }

        let (deliver_tx, deliver_rx) = mpsc::channel(16);

        self.delivery.lock().await.replace(deliver_tx);

        BatchedHandle::new(
            self.keypair.clone(),
            self.rendezvous.clone(),
            deliver_rx,
            sender,
        )
    }
}

/// A `Handle` to interact with a `BatchedMurmur` instance
pub struct BatchedHandle<I, O, S, R>
where
    I: Message + 'static,
    O: Send,
    S: Sender<BatchedMurmurMessage<I>>,
    R: RdvPolicy,
{
    signer: Signer,
    receiver: mpsc::Receiver<O>,
    sender: Arc<S>,
    policy: Arc<R>,
    sequence: AtomicU32,
    _i: PhantomData<I>,
}

impl<I, O, S, R> BatchedHandle<I, O, S, R>
where
    I: Message + 'static,
    O: Send,
    S: Sender<BatchedMurmurMessage<I>>,
    R: RdvPolicy,
{
    fn new(keypair: KeyPair, policy: Arc<R>, receiver: mpsc::Receiver<O>, sender: Arc<S>) -> Self {
        Self {
            policy,
            receiver,
            sender,
            signer: Signer::new(keypair),
            sequence: AtomicU32::new(0),
            _i: PhantomData,
        }
    }
}

#[async_trait]
impl<I, O, S, R> Handle<I, O> for BatchedHandle<I, O, S, R>
where
    I: Message,
    O: Send,
    S: Sender<BatchedMurmurMessage<I>>,
    R: RdvPolicy,
{
    type Error = BatchError;

    async fn deliver(&mut self) -> Result<O, Self::Error> {
        self.receiver.recv().await.ok_or_else(|| Channel.build())
    }

    async fn try_deliver(&mut self) -> Result<Option<O>, Self::Error> {
        use futures::{
            future::{self, Either},
            pin_mut,
        };

        let fut = self.deliver();

        pin_mut!(fut);

        match future::select(fut, future::ready(())).await {
            Either::Left((Err(e), _)) => Err(e),
            Either::Left((Ok(msg), _)) => Ok(Some(msg)),
            Either::Right((_, _)) => Ok(None),
        }
    }

    async fn broadcast(&mut self, message: &I) -> Result<(), Self::Error> {
        trace!("starting broadcast of {:?}", message);

        let signature = self.signer.sign(message).context(Sign)?;

        let payload = Payload::new(
            *self.signer.public(),
            self.sequence.fetch_add(1, Ordering::AcqRel),
            message.clone(),
            signature,
        );
        let message = BatchedMurmurMessage::Collect(payload);

        match self.policy.pick().await {
            RdvConfig::Local => todo!(),
            RdvConfig::Remote { ref peer } => self
                .sender
                .send(Arc::new(message), peer)
                .await
                .context(Broadcast),
        }
    }
}

#[derive(Clone)]
enum State<M: Message> {
    Complete(Arc<Batch<M>>),
    Pending(Arc<BatchState<M>>),
}

impl<M> State<M>
where
    M: Message + 'static,
{
    fn is_complete(&self) -> bool {
        !self.is_pending()
    }

    fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }

    fn info(&self) -> &BatchInfo {
        match self {
            Self::Complete(batch) => batch.info(),
            Self::Pending(batch) => batch.info(),
        }
    }

    async fn get_block(&self, seq: Sequence) -> Option<Block<M>> {
        match self {
            Self::Pending(state) => state.get_sequence(seq).await,
            Self::Complete(batch) => batch.get(seq),
        }
    }

    /// Check if this is ready to transition from pending to complete
    /// # Returns
    /// `Some` containing the complete batch if ready, `None` otherwise
    async fn ready(&mut self) -> Option<Arc<Batch<M>>> {
        match self {
            Self::Pending(state) => {
                if state.complete().await.is_ok() {
                    if let Ok(batch) = state.to_batch().await {
                        let batch = Arc::new(batch);
                        *self = Self::Complete(batch.clone());
                        Some(batch)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            Self::Complete(batch) => Some(batch.clone()),
        }
    }

    /// Get this `Batch`'s state as a pending state if possible
    fn to_pending(&self) -> Option<Arc<BatchState<M>>> {
        if let Self::Pending(state) = self {
            Some(state.clone())
        } else {
            None
        }
    }

    fn available(&self) -> bool {
        self.is_complete()
    }
}

impl<M> From<Arc<BatchState<M>>> for State<M>
where
    M: Message + 'static,
{
    fn from(state: Arc<BatchState<M>>) -> Self {
        Self::Pending(state)
    }
}

impl<M> From<Arc<Batch<M>>> for State<M>
where
    M: Message + 'static,
{
    fn from(batch: Arc<Batch<M>>) -> Self {
        Self::Complete(batch)
    }
}

impl<M> fmt::Display for State<M>
where
    M: Message + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Pending(batch) => write!(f, "pending batch {}", batch.info().digest()),
            Self::Complete(batch) => write!(f, "complete batch {}", batch.info().digest()),
        }
    }
}

#[cfg(any(test, feature = "test"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test")))]
/// Test utilites for `BatchedMurmur`
pub mod test {
    use super::*;

    use std::iter;

    use drop::system::sampler::AllSampler;
    use drop::system::sender::CollectingSender;

    #[allow(dead_code)]
    static SIZE: usize = DEFAULT_BLOCK_SIZE * 10;

    fn generate_sequence<M, F>(
        count: usize,
        generator: F,
    ) -> impl Iterator<Item = BatchedMurmurMessage<M>>
    where
        M: Message,
        F: FnMut(usize) -> BatchedMurmurMessage<M>,
    {
        (0..count).map(generator)
    }

    /// Generate a sequence of `Collect` messages
    pub fn generate_collect<M, F>(
        count: usize,
        generator: F,
    ) -> impl Iterator<Item = BatchedMurmurMessage<M>>
    where
        M: Message,
        F: Fn(usize) -> M,
    {
        generate_sequence(count, move |x| {
            let mut signer = Signer::random();
            let source = *signer.public();

            let content = (generator)(x);
            let signature = signer.sign(&content).expect("sign failed");

            let payload = Payload::new(source, x as Sequence, content, signature);

            BatchedMurmurMessage::Collect(payload)
        })
    }

    /// Generate a sequence of `Pull` messages for the entirety of the provided `Batch`
    pub fn generate_pull<M>(batch: &Batch<M>) -> impl Iterator<Item = BatchedMurmurMessage<M>> + '_
    where
        M: Message,
    {
        let size = batch.blocks().count();
        let digest = *batch.info().digest();

        generate_sequence(size, move |x| {
            let block = batch.blocks().nth(x).unwrap();
            let seq = block.sequence();
            let digest = digest;
            let id = BlockId::new(digest, seq);

            BatchedMurmurMessage::Pull(id)
        })
    }

    /// Generate a sequence of `Transmit` messages that contains the whole `Batch`
    pub fn generate_transmit<M>(batch: Batch<M>) -> impl Iterator<Item = BatchedMurmurMessage<M>>
    where
        M: Message,
    {
        let info = *batch.info();
        let size = batch.blocks().count();
        let mut blocks = batch.into_blocks();

        generate_sequence(size, move |_| {
            let block = blocks.next().expect("invalid batch size");
            let sequence = block.sequence();

            BatchedMurmurMessage::Transmit(info, sequence, block)
        })
    }

    /// Run the select processor as if all messages in the message `Iterator` were received from
    /// the network using the keys in the keys `Iterator` in a cycle as sources.
    pub async fn run<M, R, I1, I2>(
        mut murmur: BatchedMurmur<M, R>,
        messages: I1,
        keys: I2,
    ) -> (
        Arc<BatchedMurmur<M, R>>,
        Arc<CollectingSender<BatchedMurmurMessage<M>>>,
    )
    where
        M: Message + 'static,
        R: RdvPolicy + 'static,
        I1: IntoIterator<Item = BatchedMurmurMessage<M>>,
        I2: IntoIterator<Item = PublicKey> + Clone,
        I2::IntoIter: Clone,
    {
        let sampler = Arc::new(AllSampler::default());
        let sender = Arc::new(CollectingSender::new(keys.clone()));
        let delivery = messages.into_iter().zip(keys.into_iter().cycle());

        murmur.output(sampler, sender.clone()).await;

        let murmur = Arc::new(murmur);

        let futures =
            iter::repeat(murmur.clone())
                .zip(delivery)
                .map(|(murmur, (message, from))| {
                    let sender = sender.clone();

                    tokio::task::spawn(async move {
                        murmur
                            .process(Arc::new(message), from, sender)
                            .await
                            .expect("processing failed")
                    })
                });

        futures::future::join_all(futures)
            .await
            .into_iter()
            .for_each(Result::unwrap);

        (murmur, sender)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sponge_insertion() {
        use drop::test::keyset;

        let policy = Fixed::new_local();
        let keypair = KeyPair::random();
        let peers = keyset(50);
        let murmur = BatchedMurmur::new(keypair.clone(), policy);
        let payloads = generate_collect(SIZE, |x| x);

        let (murmur, _) = run(murmur, payloads, peers).await;

        assert_eq!(
            murmur.sponge.lock().await.len(),
            SIZE,
            "wrong number of message in sponge"
        );

        let batch = murmur
            .sponge
            .lock()
            .await
            .drain_to_batch(DEFAULT_BLOCK_SIZE);

        assert_eq!(
            batch.len() as usize,
            SIZE,
            "wrong number of payloads in batch"
        );

        batch
            .blocks()
            .for_each(|block| block.verify(&keypair).expect("block failed to verify"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sponge_fill() {
        use drop::test::keyset;

        drop::test::init_logger();

        let keypair = KeyPair::random();
        let murmur = BatchedMurmur::new(keypair.clone(), Fixed::new_local());
        let peers = keyset(50);
        let payloads = generate_collect(DEFAULT_SPONGE_THRESHOLD + 1, |x| x * 2);

        let (murmur, sender) = run(murmur, payloads, peers).await;

        assert_eq!(
            murmur.sponge.lock().await.len(),
            1,
            "too many message left in sponge"
        );

        let announce = sender
            .messages()
            .await
            .into_iter()
            .find_map(|msg| match msg.1.deref() {
                BatchedMurmurMessage::Announce(info, true) => Some(*info),
                _ => None,
            })
            .expect("did not announce batch");

        assert_eq!(announce.size(), DEFAULT_SPONGE_THRESHOLD);
    }

    #[tokio::test]
    async fn batch_announce() {
        use super::sync::test::generate_batch;

        use drop::test::keyset;

        drop::test::init_logger();

        let batch = generate_batch(SIZE / DEFAULT_BLOCK_SIZE);
        let info = *batch.info();
        let announce = BatchedMurmurMessage::Announce(*batch.info(), true);
        let messages = iter::once(announce).chain(generate_transmit(batch));
        let keys: Vec<_> = keyset(SIZE / 100).collect();
        let murmur = BatchedMurmur::new(KeyPair::random(), Fixed::new_local());

        let (murmur, sender) = run(murmur, messages, keys).await;

        murmur
            .batches
            .read()
            .await
            .get(info.digest())
            .expect("no complete batch registered");

        let outgoing = sender.messages().await;

        assert!(outgoing.len() >= 2, "not enough messages sent");

        assert!(outgoing.iter().any(
            |msg| matches!(msg.1.deref(), &BatchedMurmurMessage::Announce(i, true) if info == i)
        ));
    }

    #[tokio::test]
    async fn multiple_block_sources() {
        use super::sync::test::generate_batch;

        use drop::test::keyset;

        drop::test::init_logger();

        let peer_count = SIZE / 100;

        let batch = generate_batch(SIZE / DEFAULT_BLOCK_SIZE);
        let info = *batch.info();
        let announce = BatchedMurmurMessage::Announce(*batch.info(), true);
        let messages = iter::repeat(announce.clone())
            .take(peer_count)
            .chain(generate_transmit(batch));
        let keys: Vec<_> = keyset(peer_count).collect();
        let murmur = BatchedMurmur::new(KeyPair::random(), Fixed::new_local());

        let (_, sender) = run(murmur, messages, keys).await;
        let messages = sender.messages().await;

        for blockid in (0..info.sequence()).map(|seq| BlockId::new(*info.digest(), seq)) {
            let pulls = messages
                .iter()
                .filter(
                    |msg| matches!(msg.1.deref(), &BatchedMurmurMessage::Pull(id)if blockid == id),
                )
                .count();

            assert_eq!(pulls, 1, "block pulled more than once without timeout");
        }

        messages
            .iter()
            .find(|msg| matches!(msg.1.deref(), &BatchedMurmurMessage::Announce(_, true)))
            .expect("did not announce completed batch");
    }

    #[tokio::test]
    async fn block_pulling() {
        use super::sync::test::generate_batch;

        use drop::test::keyset;

        drop::test::init_logger();

        let batch = generate_batch(SIZE / DEFAULT_BLOCK_SIZE);
        let info = *batch.info();
        let pulls = generate_pull(&batch);
        let murmur = BatchedMurmur::new(KeyPair::random(), Fixed::new_local());
        let keys: Vec<_> = keyset(SIZE / 100).collect();

        murmur.insert_batch(batch.clone()).await;

        let (_, sender) = run(murmur, pulls, keys).await;

        let sent = sender.messages().await;

        for block in batch.blocks() {
            let sequence = block.sequence();

            assert!(sent.iter().any(
                |(_, msg)| matches!(msg.deref(), &BatchedMurmurMessage::Transmit(i, s, _) if info == i && s == sequence)
            ), "missing transmit message for block");
        }
    }

    #[tokio::test]
    async fn subscribe_announces_batch() {
        use super::sync::test::generate_batch;

        use drop::test::keyset;

        static SUBSCRIBERS: usize = 10;

        drop::test::init_logger();

        let batch = generate_batch(SIZE / DEFAULT_BLOCK_SIZE);
        let murmur = BatchedMurmur::new(KeyPair::random(), Fixed::new_local());
        let keys: Vec<_> = keyset(50).collect();

        murmur.insert_batch(batch).await;

        let messages = iter::repeat(BatchedMurmurMessage::Subscribe).take(SUBSCRIBERS);

        let (murmur, sender) = run(murmur, messages, keys.clone()).await;

        let sent = sender.messages().await;

        let (dest, msg): (HashSet<_>, Vec<_>) = sent.into_iter().unzip();

        let announce = msg
            .into_iter()
            .filter(|msg| matches!(msg.deref(), &BatchedMurmurMessage::Announce(_, true)))
            .count();

        assert_eq!(
            announce,
            keys.len(),
            "did not announce batch to new subscribers"
        );

        assert_eq!(
            dest.difference(murmur.gossip.read().await.deref()).count(),
            0,
            "did not announce to every subscribers"
        );
    }

    #[tokio::test]
    async fn handle_delivery() {
        use super::sync::test::generate_batch;

        use drop::test::{keyset, DummyManager};

        drop::test::init_logger();

        let keypair = KeyPair::random();
        let batch = generate_batch(SIZE / DEFAULT_BLOCK_SIZE);
        let info = *batch.info();
        let murmur = BatchedMurmur::new(keypair.clone(), Fixed::new_local());
        let keys: Vec<_> = keyset(50).collect();
        let announce = BatchedMurmurMessage::Announce(*batch.info(), true);
        let messages =
            iter::repeat(keys[0]).zip(iter::once(announce).chain(generate_transmit(batch)));
        let mut manager = DummyManager::with_key(messages, keys);

        let mut handle = manager.run(murmur).await;

        let recv: Arc<Batch<u32>> = handle.deliver().await.expect("deliver failed");

        assert_eq!(recv.info(), &info, "delivered batch has different metadata");

        recv.blocks()
            .for_each(|block| block.verify(&keypair).expect("invalid block"));
    }

    #[tokio::test]
    async fn deliver_then_announce() {
        use super::sync::test::generate_batch;

        use drop::system::sampler::AllSampler;
        use drop::test::keyset;

        drop::test::init_logger();

        let public = keyset(1).next().unwrap();
        let sender = Arc::new(CollectingSender::new(iter::once(public)));
        let sampler = Arc::new(AllSampler::default());
        let batch = generate_batch(1);
        let mut murmur = BatchedMurmur::new(KeyPair::random(), Fixed::new_local());
        let announce = BatchedMurmurMessage::Announce(*batch.info(), true);
        let messages = iter::once(announce.clone())
            .chain(generate_transmit(batch))
            .chain(iter::once(announce))
            .map(Arc::new);
        let mut handle = murmur.output(sampler, sender.clone()).await;

        let murmur = Arc::new(murmur);

        futures::future::join_all(
            iter::repeat(murmur.clone())
                .zip(messages)
                .map(|(murmur, message)| murmur.process(message, public, sender.clone())),
        )
        .await;

        handle.deliver().await.expect("delivery failed");

        let batches = murmur.batches.read().await;

        assert_eq!(batches.len(), 1, "batch was unregistered after delivery");
        assert!(
            batches.values().all(State::is_complete),
            "batch was not set as complete"
        );
    }
}
