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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use drop::async_trait;
use drop::crypto::hash::Digest;
use drop::crypto::key::exchange::PublicKey;
use drop::crypto::sign::{KeyPair, SignError, VerifyError};
use drop::system::{message, Handle, Message, Processor, Sampler, Sender, SenderError};

use futures::future::OptionFuture;

use postage::dispatch;
use postage::prelude::*;

use serde::{Deserialize, Serialize};

use snafu::{OptionExt, ResultExt, Snafu};

use tokio::sync::{mpsc, RwLock};
use tokio::task;
use tokio::time;

use tracing::{debug, error, info, trace, warn};

/// Type for sequence numbers of a `Block`
pub type Sequence = u32;

mod config;
pub use config::{MurmurConfig, MurmurConfigBuilder};

mod provider;
use provider::ProviderHandle;

mod sponge;
use sponge::SpongeHandle;

mod rdv;
pub use rdv::*;

mod structs;
pub use structs::{Batch, BatchInfo, Payload};
pub(self) use structs::{Block, BlockId, Sponge};

mod sync;
use sync::BatchState;

#[derive(Debug, Snafu)]
/// Errors encountered when processing a message
pub enum MurmurError {
    #[snafu(display("instance has died"))]
    /// Channel used by instance is dead
    Channel,
    #[snafu(display("message signing failed: {}", source))]
    /// Error signing mesage
    Sign {
        /// Underlying error cause
        source: SignError,
    },
    #[snafu(display("network error:{}", source))]
    /// Network error encountered
    Network {
        /// Error source
        source: SenderError,
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
/// Messages exchanged by [`Murmur`]
///
/// [`Murmur`]: self::Murmur
pub enum MurmurMessage<M: Message> {
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

impl<M> From<Payload<M>> for MurmurMessage<M>
where
    M: Message,
{
    fn from(payload: Payload<M>) -> Self {
        Self::Collect(payload)
    }
}

/// A version of Murmur that provides multiple optimisation over [`Murmur]` such as
/// latency selection of peers, batching and bittorrent-like block distribution.
/// It also supports multi-shot broadcasting, e.g. one sender can send multiple block
/// using the same instance of [`Murmur]` as well as receive multiple messages using
/// the same instance
///
/// [`Murmur`]: crate::::Murmur
pub struct Murmur<M: Message, R: RdvPolicy> {
    keypair: KeyPair,
    batches: RwLock<HashMap<Digest, State<M>>>,

    providers: ProviderHandle,

    rendezvous: Arc<R>,
    sponge: SpongeHandle<M>,

    delivery: Option<dispatch::Sender<Arc<Batch<M>>>>,

    config: MurmurConfig,

    gossip: Arc<RwLock<HashSet<PublicKey>>>,
}

impl<M, R> Murmur<M, R>
where
    M: Message + 'static,
    R: RdvPolicy,
{
    /// Create a new `Murmur` instance
    pub fn new(keypair: KeyPair, rendezvous: R, config: MurmurConfig) -> Self {
        Self {
            keypair,
            config,
            rendezvous: Arc::new(rendezvous),
            batches: Default::default(),
            gossip: Default::default(),
            sponge: SpongeHandle::new(
                config.channel_cap,
                config.sponge_threshold,
                config.block_size,
            ),
            delivery: Default::default(),
            providers: Default::default(),
        }
    }

    /// Announces the specified `Batch` to gossip peers
    async fn announce<S: Sender<MurmurMessage<M>> + 'static>(
        &self,
        info: BatchInfo,
        available: bool,
        sender: Arc<S>,
    ) -> Result<(), MurmurError> {
        Self::announce_with_set(info, available, sender, self.gossip.read().await.iter()).await
    }

    async fn announce_with_set<S>(
        info: BatchInfo,
        available: bool,
        sender: Arc<S>,
        to: impl Iterator<Item = &PublicKey> + Send,
    ) -> Result<(), MurmurError>
    where
        S: Sender<MurmurMessage<M>>,
    {
        let message = MurmurMessage::Announce(info, available);

        debug!(
            "announcing new batch {} of size {} to peers",
            info.digest(),
            info.size()
        );

        sender.send_many(message, to).await.context(Network)
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

    async fn try_deliver(&self, digest: &Digest) -> Result<Option<Arc<Batch<M>>>, MurmurError> {
        let mut guard = self.batches.write().await;

        match guard.entry(*digest) {
            Entry::Vacant(_) => Ok(None),
            Entry::Occupied(mut e) => Ok(e.get_mut().ready().await),
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
    ) -> Result<(), MurmurError>
    where
        S: Sender<MurmurMessage<M>>,
    {
        let message = MurmurMessage::Advertise(info, vec![sequence]);

        debug!(
            "advertising block {} from {} to peers",
            sequence,
            info.digest()
        );

        sender
            .send_many(message, self.gossip.read().await.iter())
            .await
            .context(Network)
    }

    async fn pull_missing_blocks<S>(
        &self,
        info: BatchInfo,
        available: impl Iterator<Item = Sequence>,
        from: PublicKey,
        sender: Arc<S>,
    ) -> Result<(), MurmurError>
    where
        S: Sender<MurmurMessage<M>>,
    {
        if self.is_delivered(info.digest()).await {
            debug!("already delivered {}, not requesting blocks", info);
            self.providers.purge(info).await;
            return Ok(());
        }

        self.batches
            .write()
            .await
            .entry(*info.digest())
            .or_insert_with(|| State::Pending(Arc::new(BatchState::new(info))));

        for sequence in available {
            let id = BlockId::new(*info.digest(), sequence);

            self.providers.register_provider(id, from).await;

            if let Some(provider) = self.providers.best_provider(id).await {
                let message = MurmurMessage::Pull(id);

                debug!("pulling {} from {}", id, from);

                sender.send(message, &provider).await.context(Network)?;
            } else {
                debug!("not pulling {}, already pending request", id);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<M, S, R> Processor<MurmurMessage<M>, Payload<M>, Arc<Batch<M>>, S> for Murmur<M, R>
where
    M: Message + 'static,
    R: RdvPolicy + 'static,
    S: Sender<MurmurMessage<M>> + 'static,
{
    type Handle = MurmurHandle<M, Arc<Batch<M>>, S, R>;

    type Error = MurmurError;

    async fn process(
        &self,
        message: MurmurMessage<M>,
        from: PublicKey,
        sender: Arc<S>,
    ) -> Result<(), Self::Error> {
        match message {
            MurmurMessage::Announce(info, has) => {
                if has {
                    self.pull_missing_blocks(info, 0..info.sequence(), from, sender)
                        .await?;
                }
            }

            MurmurMessage::Advertise(info, blocks) => {
                trace!(
                    "{} advertising {} blocks from batch {}",
                    from,
                    blocks.len(),
                    info
                );

                self.pull_missing_blocks(info, blocks.iter().copied(), from, sender)
                    .await?;
            }

            MurmurMessage::Pull(blockid) => {
                trace!(
                    "request for block {}  for batch {} from {}",
                    blockid.sequence(),
                    blockid.digest(),
                    from
                );

                if let Some(block) = self.get_block(&blockid).await {
                    debug!(
                        "sending block {} of batch {} to {}",
                        blockid.sequence(),
                        blockid.digest(),
                        from
                    );
                    let info = self.batchinfo(&blockid).await.context(UnknownBatch {
                        digest: *blockid.digest(),
                    })?;

                    let message = MurmurMessage::Transmit(info, blockid.sequence(), block);

                    sender.send(message, &from).await.context(Network)?;
                } else {
                    warn!(
                        "peer requested block {} from batch {} that we don't have yet",
                        blockid.sequence(),
                        blockid.digest()
                    );
                }
            }

            MurmurMessage::Transmit(info, sequence, block) => {
                if self.is_delivered(info.digest()).await {
                    debug!("late transmit for block {} of {}", sequence, info);
                    return Ok(());
                }

                let blockid = BlockId::new(*info.digest(), sequence);

                self.providers.register_response(blockid, from).await;

                block.verify(&self.keypair).context(InvalidBlock { from })?;

                debug!(
                    "received valid block {} for batch {} from {}",
                    sequence,
                    info.digest(),
                    from
                );

                if self.insert_block(blockid, block.clone()).await {
                    trace!(
                        "registered new block {} for {}",
                        blockid.sequence(),
                        info.digest()
                    );

                    if let Some(batch) = self.try_deliver(info.digest()).await? {
                        info!("batch {} is complete", info.digest());
                        self.announce(info, true, sender).await?;

                        self.providers.purge(info).await;

                        self.delivery
                            .as_ref()
                            .map(Clone::clone)
                            .context(Setup)?
                            .send(batch)
                            .await
                            .map_err(|_| Channel.build())?;
                    } else {
                        self.advertise(info, sequence, sender.clone()).await?;
                    }
                }
            }

            MurmurMessage::Collect(payload) => {
                payload
                    .verify(&self.keypair)
                    .context(InvalidBlock { from })?;

                if let Some(batch) = self.sponge.collect(payload).await {
                    let info = *batch.info();

                    self.insert_batch(batch).await;
                    self.announce(info, true, sender).await?;
                }
            }

            MurmurMessage::Subscribe => {
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
                    //             let message = MurmurMessage::Announce(batch.info(), true);
                    //
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
                        let message = MurmurMessage::Announce(*batch.info(), available);

                        sender.send(message, &from).await.context(Network)?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn setup<SA: Sampler>(&mut self, sampler: Arc<SA>, sender: Arc<S>) -> Self::Handle {
        let keys = sender.keys().await;
        let sample = sampler
            .sample(keys.iter().copied(), self.config.murmur_gossip_size)
            .await
            .expect("sampling failed");

        debug!(
            "initial sampling finished with {} remote peers",
            sample.len()
        );

        self.gossip.write().await.extend(sample);

        sender
            .send_many(MurmurMessage::Subscribe, self.gossip.read().await.iter())
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

        let sponge = self.sponge.clone();
        let timeout = self.config.batch_delay();
        let gossip = self.gossip.clone();
        let to_sender = sender.clone();

        task::spawn(async move {
            info!("started batch timeout monitoring");

            loop {
                time::sleep(timeout).await;

                debug!("timeout reached checking batch status");

                if let Some(batch) = sponge.force().await {
                    debug!("force created a batch after failing to reach threshold");

                    if let Err(e) = Self::announce_with_set(
                        *batch.info(),
                        true,
                        to_sender.clone(),
                        gossip.read().await.iter(),
                    )
                    .await
                    {
                        error!("failed to announce batch to peers: {}", e);
                    }
                }
            }
        });

        let (deliver_tx, deliver_rx) = dispatch::channel(self.config.channel_cap);

        self.delivery.replace(deliver_tx);

        MurmurHandle::new(
            self.rendezvous.clone(),
            deliver_rx,
            sender,
            self.sponge.clone(),
        )
    }

    async fn disconnect<SA: Sampler>(&self, peer: PublicKey, sender: Arc<S>, sampler: Arc<SA>) {
        if self.gossip.read().await.contains(&peer) {
            debug!("peer {} from our gossip set was disconnected", peer);

            let keys = sender.keys().await;
            let mut gossip = self.gossip.write().await;

            gossip.remove(&peer);

            let not_in_gossip = keys.into_iter().filter(|x| !gossip.contains(&x));

            // if the sampler fails we already have all known peers in our gossip set
            if let Ok(new) = sampler.sample(not_in_gossip, 1).await {
                debug!("resampled for {} new peers", new.len());

                gossip.extend(new);
            }
        }
    }

    async fn garbage_collection(&self) {
        self.batches
            .write()
            .await
            .retain(|_, batch| !batch.expired(self.config.batch_expiration()));
    }
}

impl<M> Default for Murmur<M, Fixed>
where
    M: Message + 'static,
{
    fn default() -> Self {
        Self::new(
            KeyPair::random(),
            Fixed::new_local(),
            MurmurConfig::default(),
        )
    }
}

/// A [`Handle`] to interact with a [`Murmur`] instance
///
/// [`Murmur`]: self::Murmur
/// [`Handle`]: drop::system::manager::Handle
pub struct MurmurHandle<I, O, S, R>
where
    I: Message + 'static,
    O: Send,
    S: Sender<MurmurMessage<I>>,
    R: RdvPolicy,
{
    receiver: dispatch::Receiver<O>,
    sender: Arc<S>,
    policy: Arc<R>,
    sponge: SpongeHandle<I>,
}

impl<I, O, S, R> MurmurHandle<I, O, S, R>
where
    I: Message + 'static,
    O: Send,
    S: Sender<MurmurMessage<I>>,
    R: RdvPolicy,
{
    fn new(
        policy: Arc<R>,
        receiver: dispatch::Receiver<O>,
        sender: Arc<S>,
        sponge: SpongeHandle<I>,
    ) -> Self {
        Self {
            receiver,
            sender,
            policy,
            sponge,
        }
    }
}

#[async_trait]
impl<I, O, S, R> Handle<Payload<I>, O> for MurmurHandle<I, O, S, R>
where
    I: Message,
    O: Send,
    S: Sender<MurmurMessage<I>>,
    R: RdvPolicy,
{
    type Error = MurmurError;

    async fn deliver(&mut self) -> Result<O, Self::Error> {
        self.receiver.recv().await.ok_or_else(|| Channel.build())
    }

    async fn try_deliver(&mut self) -> Result<Option<O>, Self::Error> {
        use postage::stream::TryRecvError;

        match self.receiver.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(TryRecvError::Pending) => Ok(None),
            Err(_) => Channel.fail(),
        }
    }

    async fn broadcast(&mut self, message: &Payload<I>) -> Result<(), Self::Error> {
        trace!("starting broadcast of {:?}", message);

        let payload = message.clone();

        match self.policy.pick().await {
            RdvConfig::Local => {
                self.sponge.collect_only(payload).await;
                Ok(())
            }
            RdvConfig::Remote { ref peer } => {
                let message = payload.into();

                self.sender.send(message, peer).await.context(Network)
            }
        }
    }
}

// deriving the trait automatically doesn't work, rustc complains that
// all generic paramters are not Clone although they are in an Arc...
impl<I, O, S, R> Clone for MurmurHandle<I, O, S, R>
where
    I: Message,
    O: Send,
    S: Sender<MurmurMessage<I>>,
    R: RdvPolicy,
{
    fn clone(&self) -> Self {
        Self {
            receiver: self.receiver.clone(),
            sender: self.sender.clone(),
            policy: self.policy.clone(),
            sponge: self.sponge.clone(),
        }
    }
}

#[derive(Clone)]
enum State<M: Message> {
    Complete(Arc<Batch<M>>, Instant),
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
            Self::Complete(batch, _) => batch.info(),
            Self::Pending(batch) => batch.info(),
        }
    }

    async fn get_block(&self, seq: Sequence) -> Option<Block<M>> {
        match self {
            Self::Pending(state) => state.get_sequence(seq).await,
            Self::Complete(batch, _) => batch.get(seq),
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
                        *self = Self::Complete(batch.clone(), Instant::now());
                        Some(batch)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            Self::Complete(batch, _) => Some(batch.clone()),
        }
    }

    fn expired(&self, expiration: Duration) -> bool {
        match self {
            Self::Complete(_, time) => Instant::now().duration_since(*time) >= expiration,
            _ => false,
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
        Self::Complete(batch, Instant::now())
    }
}

impl<M> fmt::Display for State<M>
where
    M: Message + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Pending(batch) => write!(f, "pending batch {}", batch.info().digest()),
            Self::Complete(batch, _) => write!(f, "complete batch {}", batch.info().digest()),
        }
    }
}

#[cfg(any(test, feature = "test"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test")))]
/// Test utilites for [`Murmur`]
///
/// [`Murmur`]: self::Murmur
pub mod test {
    use super::*;

    use std::iter;

    pub use super::sync::test::*;

    use drop::system::AllSampler;
    use drop::system::CollectingSender;

    use lazy_static::lazy_static;

    #[allow(dead_code)]
    lazy_static! {
        static ref SIZE: usize = MurmurConfig::default().block_size * 10;
        static ref DEFAULT_SPONGE_THRESHOLD: usize = MurmurConfig::default().sponge_threshold;
        static ref DEFAULT_BLOCK_SIZE: usize = MurmurConfig::default().block_size;
    }

    fn generate_sequence<M, F>(count: usize, generator: F) -> impl Iterator<Item = MurmurMessage<M>>
    where
        M: Message,
        F: FnMut(usize) -> MurmurMessage<M>,
    {
        (0..count).map(generator)
    }

    /// Generate a sequence of `Collect` messages
    pub fn generate_collect<M, F>(
        count: usize,
        generator: F,
    ) -> impl Iterator<Item = MurmurMessage<M>>
    where
        M: Message,
        F: Fn(usize) -> M,
    {
        use drop::crypto::sign::Signer;

        generate_sequence(count, move |x| {
            let mut signer = Signer::random();
            let source = *signer.public();

            let content = (generator)(x);
            let signature = signer.sign(&content).expect("sign failed");

            let payload = Payload::new(source, x as Sequence, content, signature);

            MurmurMessage::Collect(payload)
        })
    }

    /// Generate a sequence of `Pull` messages for the entirety of the provided `Batch`
    pub fn generate_pull<M>(batch: &Batch<M>) -> impl Iterator<Item = MurmurMessage<M>> + '_
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

            MurmurMessage::Pull(id)
        })
    }

    /// Generate a sequence of `Transmit` messages that contains the whole `Batch`
    pub fn generate_transmit<M>(batch: Batch<M>) -> impl Iterator<Item = MurmurMessage<M>>
    where
        M: Message,
    {
        let info = *batch.info();
        let size = batch.blocks().count();
        let mut blocks = batch.into_blocks();

        generate_sequence(size, move |_| {
            let block = blocks.next().expect("invalid batch size");
            let sequence = block.sequence();

            MurmurMessage::Transmit(info, sequence, block)
        })
    }

    /// Run the select processor as if all messages in the message `Iterator` were received from
    /// the network using the keys in the keys `Iterator` in a cycle as sources.
    pub async fn run<M, R, I1, I2>(
        mut murmur: Murmur<M, R>,
        messages: I1,
        keys: I2,
    ) -> (Arc<Murmur<M, R>>, Arc<CollectingSender<MurmurMessage<M>>>)
    where
        M: Message + 'static,
        R: RdvPolicy + 'static,
        I1: IntoIterator<Item = MurmurMessage<M>>,
        I2: IntoIterator<Item = PublicKey> + Clone,
        I2::IntoIter: Clone,
    {
        use futures::stream::{FuturesUnordered, StreamExt};

        let sampler = Arc::new(AllSampler::default());
        let sender = Arc::new(CollectingSender::new(keys.clone()));
        let delivery = messages.into_iter().zip(keys.into_iter().cycle());

        let _handle = murmur.setup(sampler, sender.clone()).await;

        let murmur = Arc::new(murmur);

        let futures: FuturesUnordered<_> = iter::repeat(murmur.clone())
            .zip(delivery)
            .map(|(murmur, (message, from))| {
                let sender = sender.clone();

                tokio::task::spawn(async move {
                    murmur
                        .process(message, from, sender)
                        .await
                        .expect("processing failed")
                })
            })
            .collect();

        futures.map(Result::unwrap).collect::<Vec<_>>().await;

        (murmur, sender)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sponge_fill() {
        use drop::test::keyset;

        drop::test::init_logger();

        let config = MurmurConfig {
            batch_delay: 200 * 1000,
            ..Default::default()
        };
        let murmur = Murmur::new(KeyPair::random(), Fixed::new_local(), config);
        let peers = keyset(50);
        let payloads = generate_collect(config.sponge_threshold + 1, |x| x * 2);

        let (_, sender) = run(murmur, payloads, peers).await;

        let announce = sender
            .messages()
            .await
            .into_iter()
            .find_map(|msg| match msg.1 {
                MurmurMessage::Announce(info, true) => Some(info),
                _ => None,
            })
            .expect("no batch announced");

        assert_eq!(announce.size(), config.sponge_threshold);
    }

    #[tokio::test]
    async fn batch_announce() {
        use drop::test::keyset;

        drop::test::init_logger();

        let batch = generate_batch(*SIZE / *DEFAULT_BLOCK_SIZE);
        let info = *batch.info();
        let announce = MurmurMessage::Announce(*batch.info(), true);
        let messages = iter::once(announce).chain(generate_transmit(batch));
        let keys: Vec<_> = keyset(*SIZE / 100).collect();
        let murmur = Murmur::default();

        let (murmur, sender) = run(murmur, messages, keys).await;

        murmur
            .batches
            .read()
            .await
            .get(info.digest())
            .expect("no complete batch registered");

        let outgoing = sender.messages().await;

        assert!(outgoing.len() >= 2, "not enough messages sent");

        assert!(outgoing
            .iter()
            .any(|msg| matches!(msg.1, MurmurMessage::Announce(i, true) if info == i)));
    }

    #[tokio::test]
    async fn multiple_block_sources() {
        use drop::test::keyset;

        drop::test::init_logger();

        let peer_count = *SIZE / 100;

        let batch = generate_batch(*SIZE / *DEFAULT_BLOCK_SIZE);
        let info = *batch.info();
        let announce = MurmurMessage::Announce(*batch.info(), true);
        let messages = iter::repeat(announce.clone())
            .take(peer_count)
            .chain(generate_transmit(batch));
        let keys: Vec<_> = keyset(peer_count).collect();
        let murmur = Murmur::default();

        let (_, sender) = run(murmur, messages, keys).await;
        let messages = sender.messages().await;

        for blockid in (0..info.sequence()).map(|seq| BlockId::new(*info.digest(), seq)) {
            let pulls = messages
                .iter()
                .filter(|msg| matches!(msg.1, MurmurMessage::Pull(id) if blockid == id))
                .count();

            assert_eq!(
                pulls, 1,
                "{} pulled more than once without timeout",
                blockid
            );
        }

        messages
            .iter()
            .find(|msg| matches!(msg.1, MurmurMessage::Announce(_, true)))
            .expect("did not announce completed batch");
    }

    #[tokio::test]
    async fn block_pulling() {
        use drop::test::keyset;

        drop::test::init_logger();

        let batch = generate_batch(*SIZE / *DEFAULT_BLOCK_SIZE);
        let info = *batch.info();
        let pulls = generate_pull(&batch);
        let murmur = Murmur::default();
        let keys: Vec<_> = keyset(*SIZE / 100).collect();

        murmur.insert_batch(batch.clone()).await;

        let (_, sender) = run(murmur, pulls, keys).await;

        let sent = sender.messages().await;

        for block in batch.blocks() {
            let sequence = block.sequence();

            assert!(sent.iter().any(
                |(_, msg)| matches!(msg, MurmurMessage::Transmit(i, s, _) if info == *i && *s == sequence)
            ), "missing transmit message for block");
        }
    }

    #[tokio::test]
    async fn subscribe_announces_batch() {
        use drop::test::keyset;

        static SUBSCRIBERS: usize = 10;
        drop::test::init_logger();

        let batch = generate_batch(*SIZE / *DEFAULT_BLOCK_SIZE);
        let murmur = Murmur::default();
        let keys: Vec<_> = keyset(50).collect();

        murmur.insert_batch(batch).await;

        let messages = iter::repeat(MurmurMessage::Subscribe).take(SUBSCRIBERS);

        let (murmur, sender) = run(murmur, messages, keys.clone()).await;

        let sent = sender.messages().await;

        let (dest, msg): (HashSet<_>, Vec<_>) = sent.into_iter().unzip();

        let announce = msg
            .into_iter()
            .filter(|msg| matches!(msg, MurmurMessage::Announce(_, true)))
            .count();

        assert_eq!(
            announce,
            keys.len(),
            "did not announce batch to new subscribers"
        );

        assert_eq!(
            dest.difference(&*murmur.gossip.read().await).count(),
            0,
            "did not announce to every subscribers"
        );
    }

    #[tokio::test]
    async fn handle_delivery() {
        use drop::test::{keyset, DummyManager};

        drop::test::init_logger();

        let keypair = KeyPair::random();
        let batch = generate_batch(*SIZE / *DEFAULT_BLOCK_SIZE);
        let info = *batch.info();
        let murmur = Murmur::default();
        let keys: Vec<_> = keyset(50).collect();
        let announce = MurmurMessage::Announce(*batch.info(), true);
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
        use drop::system::AllSampler;
        use drop::test::keyset;

        use futures::stream::{FuturesUnordered, StreamExt};

        drop::test::init_logger();

        let keys: Vec<_> = keyset(*SIZE).collect();
        let sender = Arc::new(CollectingSender::new(keys.iter().copied()));
        let sampler = Arc::new(AllSampler::default());
        let batch = generate_batch(1);
        let mut murmur = Murmur::default();
        let announce = MurmurMessage::Announce(*batch.info(), true);
        let messages = iter::once(announce.clone())
            .chain(generate_transmit(batch))
            .chain(iter::once(announce));
        let messages = keys.clone().into_iter().cycle().zip(messages);

        let mut handle = murmur.setup(sampler, sender.clone()).await;

        let murmur = Arc::new(murmur);

        let futures: FuturesUnordered<_> = iter::repeat((murmur.clone(), sender))
            .zip(messages)
            .map(|((murmur, sender), (from, msg))| async move {
                murmur.process(msg, from, sender).await
            })
            .collect();

        futures
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .for_each(|x| x.expect("processing failed"));

        handle.deliver().await.expect("delivery failed");

        let batches = murmur.batches.read().await;

        assert_eq!(batches.len(), 1, "batch was unregistered after delivery");
        assert!(
            batches.values().all(State::is_complete),
            "batch was not set as complete"
        );
    }

    #[tokio::test]
    async fn broadcast_eventually_announces() {
        use drop::crypto::sign::Signer;
        use drop::test::keyset;

        const PEERS: usize = 10;

        drop::test::init_logger();

        let keypair = KeyPair::random();
        let config = MurmurConfig {
            batch_delay: 10,
            ..Default::default()
        };

        let keys = keyset(PEERS);
        let mut murmur = Murmur::new(keypair.clone(), Fixed::new_local(), config);
        let sampler = Arc::new(AllSampler::default());
        let sender = Arc::new(CollectingSender::new(keys));

        let mut handle = murmur.setup(sampler, sender.clone()).await;

        let message = 0usize;
        let source = *keypair.public();
        let signature = Signer::new(keypair).sign(&message).expect("sign failed");

        let payload = Payload::new(source, 0, 0usize, signature);

        handle.broadcast(&payload).await.expect("broadcast failed");

        // loop while waiting for batch_delay to expire
        while !sender
            .messages()
            .await
            .into_iter()
            .any(|m| matches!(m.1, MurmurMessage::Announce(_, true)))
        {}
    }

    #[tokio::test]
    async fn disconnection() {
        use drop::test::keyset;

        drop::test::init_logger();

        let mut murmur = Murmur::<usize, _>::default();
        let keys = keyset(10).collect::<Vec<_>>();
        let sampler = Arc::new(AllSampler::default());
        let sender = Arc::new(CollectingSender::new(keys.iter().copied()));

        murmur.setup(sampler.clone(), sender).await;

        assert_eq!(murmur.gossip.read().await.len(), keys.len());

        let sender = Arc::new(CollectingSender::new(keys.iter().skip(1).copied()));

        murmur.disconnect(keys[0], sender, sampler).await;

        let gossip = murmur.gossip.read().await;

        assert!(
            !gossip.contains(&keys[0]),
            "gossip still contains disconnected peer"
        );
        assert_eq!(
            gossip.len(),
            keys.len() - 1,
            "have too many peers after disconnected"
        );
    }

    #[cfg(test)]
    async fn garbage_test_helper(expiration_delay: u64) -> Murmur<u32, Fixed> {
        let config = MurmurConfig {
            batch_expiration: expiration_delay,
            ..Default::default()
        };
        let murmur = Murmur::<u32, _>::new(KeyPair::random(), Fixed::new_local(), config);
        let batch = generate_batch(10);

        murmur.insert_batch(batch).await;

        // yes this is ugly, blame the type inferer
        <Murmur<_, _> as Processor<_, _, _, CollectingSender<MurmurMessage<u32>>>>::garbage_collection(
            &murmur,
        )
            .await;

        murmur
    }

    #[tokio::test]
    async fn garbage_collect() {
        let murmur = garbage_test_helper(0).await;

        assert!(
            murmur.batches.read().await.is_empty(),
            "garbage collection did not remove batch"
        );
    }

    #[tokio::test]
    async fn garbage_collect_early() {
        let murmur = garbage_test_helper(5).await;

        assert!(
            !murmur.batches.read().await.is_empty(),
            "garbage collection removed batch too early"
        );
    }
}
