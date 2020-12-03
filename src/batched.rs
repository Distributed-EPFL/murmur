use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use drop::async_trait;
use drop::crypto::hash::Digest;
use drop::crypto::key::exchange::PublicKey;
use drop::crypto::sign::{self, KeyPair, Signature, Signer, VerifyError};
use drop::system::manager::Handle;
use drop::system::{message, Message, Processor, Sampler, Sender};

use serde::{Deserialize, Serialize};

use snafu::{ResultExt, Snafu};

use tokio::sync::{mpsc, Mutex, RwLock};

use tracing::{debug, warn};

/// Default timeout for block re-request
pub static DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Type for sequence numbers of a `Block`
pub type Sequence = u32;

#[derive(Debug, Snafu)]
/// Errors encountered by `BatchedMurmurHandle` when delivering or broadcasting
pub enum BatchError {
    #[snafu(display("instance has died"))]
    Channel,
}

#[derive(Debug, Snafu)]
/// Errors encountered when processing a message
pub enum BatchProcessingError {
    #[snafu(display("network error:{}", source))]
    /// Network error encountered
    Network { source: drop::system::SenderError },

    #[snafu(display("recieved block with invalid signature"))]
    /// Invalid block encountered
    InvalidBlock {
        from: PublicKey,
        source: VerifyError,
    },
}

/// Information about a `Batch`
#[message]
#[derive(Copy)]
pub struct BatchInfo {
    size: u16,
    digest: Digest,
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
        if self.latency < other.latency {
            Ordering::Less
        } else if self.latency > other.latency {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

#[message]
#[derive(Copy, PartialOrd)]
pub struct BlockId {
    hash: Digest,
    sequence: Sequence,
}

impl Ord for BlockId {
    fn cmp(&self, other: &Self) -> Ordering {
        // FIXME: once drop has `Ord` `Digest`
        self.partial_cmp(other).unwrap()
    }
}

#[message]
/// A batch of blocks that is being broadcasted
pub struct Batch<M> {
    info: BatchInfo,
    blocks: Vec<Block<M>>,
}

#[message]
/// A `Block` is one part of a `Batch`
pub struct Block<M> {
    sender: sign::PublicKey,
    sequence: Sequence,
    payload: M,
    signature: Signature,
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

impl<M: Message> Block<M> {
    fn verify(&self, keypair: &KeyPair) -> Result<(), VerifyError> {
        Signer::new(keypair.clone()).verify(&self.signature, &self.sender, &self.payload)
    }
}

struct Incomplete<M: Message> {
    batch: BatchInfo,
    blocks: BTreeMap<BlockId, Block<M>>,
}

impl<M: Message> Incomplete<M> {
    fn new(batch: BatchInfo) -> Self {
        Self {
            batch,
            blocks: Default::default(),
        }
    }

    fn insert(&mut self, blockid: &BlockId, block: &Block<M>) -> bool {
        self.blocks.insert(*blockid, block.clone())
    }

    fn is_complete(&self) -> bool {
        todo!()
    }
}

#[message]
pub enum BatchedMurmurMessage<M: Message> {
    /// Peer announces a `Batch` and whether it has it
    Announce(BatchInfo, bool),
    /// Advertise the blocks we have for a `Batch`
    Advertise(BatchInfo, Vec<Digest>),
    /// Peer requests that we send them a `Block` from some `Batch`
    Pull(BlockId),
    #[serde(bound(deserialize = "M: Message"))]
    /// Peer sends a `Block` belonging to some `Batch`
    Transmit(Digest, Sequence, Block<M>),
}

/// A version of Murmur that provides multiple optimisation over `Murmur` such as
/// latency selection of peers, batching and bittorrent-like block distribution.
/// It also supports multi-shot broadcasting, e.g. one sender can send multiple block
/// using the same instance of `BatchedMurmur` as well as receive multiple messages using
/// the same instance
pub struct BatchedMurmur<M: Message> {
    keypair: KeyPair,
    batches: Mutex<HashMap<Digest, Batch<M>>>,
    pending_batches: Mutex<HashMap<Digest, Incomplete<M>>>,
    latencies: Mutex<HashMap<PublicKey, Duration>>,
    pending_requests: Mutex<HashMap<(PublicKey, Digest, Sequence), Instant>>,
    gossip: RwLock<HashSet<PublicKey>>,
}

impl<M: Message + 'static> BatchedMurmur<M> {
    /// Create a new `BatchedMurmur`
    pub fn new(keypair: KeyPair) -> Self {
        Self::common_setup(keypair)
    }

    fn common_setup(keypair: KeyPair) -> Self {
        Self {
            keypair,
            batches: Mutex::new(HashMap::default()),
            pending_batches: Mutex::new(HashMap::default()),
            latencies: Mutex::new(HashMap::default()),
            pending_requests: Mutex::new(HashMap::default()),
            gossip: RwLock::new(HashSet::default()),
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
            info.digest, info.size
        );

        sender
            .send_many(message, self.gossip.read().await.iter())
            .await
            .context(Network)
    }

    /// Advertise known blocks from a batch to a specific peer
    async fn advertise(
        &self,
        batch: BatchInfo,
        blocks: &[Digest],
        to: PublicKey,
    ) -> Result<(), BatchProcessingError> {
        todo!()
    }

    /// Update latency information for the request identified by paramters
    async fn update_latency(&self, from: PublicKey, digest: Digest, sequence: Sequence) {
        let time = match self
            .pending_requests
            .lock()
            .await
            .entry((from, digest, sequence))
        {
            Entry::Occupied(e) => e.remove_entry().1,
            Entry::Vacant(_) => return,
        };
        let latency = Instant::now().duration_since(time);

        debug!("new latency from {}: {}", from, latency.as_millis());

        self.latencies.lock().await.insert(from, latency);
    }

    /// Register a new request has being sent right now
    async fn set_pending(&self, from: PublicKey, digest: Digest, sequence: Sequence) {
        match self
            .pending_requests
            .lock()
            .await
            .entry((from, digest, sequence))
        {
            Entry::Occupied(e) => todo!("already flying request for this block"),
            Entry::Vacant(e) => e.insert(Instant::now()),
        };
    }

    async fn check_complete(&self, batch: &Digest) -> bool {
        if let Some(batch) = self.pending_batches.lock().await.get(batch) {
            if batch.is_complete() {
                todo!("transition batch to completed");
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Check if there is request pending to some peer for some block
    async fn check_pending(&self, from: PublicKey, digest: Digest, sequence: Sequence) -> bool {
        self.pending_requests
            .lock()
            .await
            .contains_key(&(from, digest, sequence))
    }

    /// Get a `Block` from a specified `Batch` as a `Transmit` message
    async fn get_block(&self, id: &BlockId) -> Option<BatchedMurmurMessage<M>> {
        if let Some(batch) = self.pending_batches.lock().await.get(&id.hash) {
            batch
                .blocks
                .get(id)
                .map(|x| BatchedMurmurMessage::Transmit(id.hash, id.sequence, x.clone()))
        } else if let Some(batch) = self.batches.lock().await.get(&id.hash) {
            todo!()
        } else {
            None
        }
    }

    async fn insert_block(&self, id: &BlockId, block: &Block<M>) -> bool {
        match self.pending_batches.lock().await.entry(id.hash) {
            Entry::Occupied(e) => todo!("check if block already exists"),
            Entry::Vacant(e) => todo!("create new block information"),
        }
    }
}

#[async_trait]
impl<M, S> Processor<BatchedMurmurMessage<M>, Batch<M>, S> for BatchedMurmur<M>
where
    M: Message + 'static,
    S: Sender<BatchedMurmurMessage<M>> + 'static,
{
    type Handle = BatchedHandle<Batch<M>>;

    type Error = BatchProcessingError;

    async fn process(
        self: Arc<Self>,
        message: Arc<BatchedMurmurMessage<M>>,
        from: PublicKey,
        sender: Arc<S>,
    ) -> Result<(), Self::Error> {
        match message.deref() {
            BatchedMurmurMessage::Announce(info, has) => {
                match self.pending_batches.lock().await.entry(info.digest) {
                    Entry::Occupied(e) => {
                        if *has {
                            todo!("add {} as provider for blocks in batch", from);
                        }
                    }
                    Entry::Vacant(e) => {
                        debug!(
                            "learned of new batch {} with {} blocks",
                            info.digest, info.size
                        );
                        e.insert(Incomplete::new(*info));
                    }
                }
            }
            BatchedMurmurMessage::Advertise(batch, blockid) => todo!(),
            BatchedMurmurMessage::Pull(blockid) => {
                if let Some(message) = self.get_block(blockid).await {
                    debug!(
                        "sending block {} of batch {} to {}",
                        blockid.sequence, blockid.hash, from
                    );

                    sender
                        .send(Arc::new(message), &from)
                        .await
                        .context(Network)?;
                } else {
                    warn!(
                        "peer requested block {} from batch {} that we don't have yet",
                        blockid.sequence, blockid.hash
                    );
                }
            }
            BatchedMurmurMessage::Transmit(batch, sequence, block) => {
                block.verify(&self.keypair).context(InvalidBlock { from })?;

                debug!(
                    "received valid block {} for batch {} from {}",
                    sequence, batch, from
                );
                let blockid = BlockId::new(batch.digest, *sequence);

                if self.insert_block(blockid, block).await {
                    todo!("announce that we have batch {}", batch);
                }
            }
        }

        Ok(())
    }

    async fn output<SA: Sampler>(&mut self, sampler: Arc<SA>, sender: Arc<S>) -> Self::Handle {
        todo!()
    }
}

/// A `Handle` to interact with a `BatchedMurmur` instance
pub struct BatchedHandle<M: Message> {
    receiver: mpsc::Receiver<M>,
    sender: Option<mpsc::Sender<M>>,
}

impl<M: Message> BatchedHandle<M> {}

#[async_trait]
impl<M: Message> Handle<M> for BatchedHandle<M> {
    type Error = BatchError;

    async fn deliver(&mut self) -> Result<M, Self::Error> {
        todo!()
    }

    async fn try_deliver(&mut self) -> Result<Option<M>, Self::Error> {
        todo!()
    }

    async fn broadcast(&mut self, message: &M) -> Result<(), Self::Error> {
        todo!()
    }
}
