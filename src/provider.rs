use super::{BatchInfo, BlockId};

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use std::time::{Duration, Instant};

use drop::crypto::key::exchange::PublicKey;

use tokio::sync::{mpsc, oneshot};
use tokio::task::{self, JoinHandle};

use tracing::trace;

/// An agent handle used for tracking latency information about remote peers
#[derive(Clone)]
pub(super) struct ProviderHandle {
    commands: mpsc::Sender<Command>,
    handle: Arc<JoinHandle<ProviderAgent>>,
}

impl ProviderHandle {
    /// Create a new  `ProvidersHandle` and spawn the associated agent
    pub fn new(cap: usize, timeout: Duration) -> Self {
        let (tx, rx) = mpsc::channel(cap);
        let agent = ProviderAgent::new(rx, timeout);
        let handle = Arc::new(agent.spawn());

        ProviderHandle {
            commands: tx,
            handle,
        }
    }

    /// Register a new block provider
    pub async fn register_provider(&self, id: BlockId, from: PublicKey) -> bool {
        let cmd = Command::Register(id, from);

        self.send_command(cmd).await
    }

    /// Get the best provider for a given block.
    /// # Returns
    /// `None` if no provider is known for block or if there is a pending request that hasn't timed out for this `Block`
    pub async fn best_provider(&self, id: BlockId) -> Option<PublicKey> {
        let (tx, rx) = oneshot::channel();
        let cmd = Command::Best(id, Instant::now(), tx);

        self.commands.send(cmd).await.ok()?;

        rx.await.ok().flatten()
    }

    /// Register a response for some block and update latency information
    /// # Returns
    /// `false` if the associated has isn't running anymore agent
    pub async fn register_response(&self, id: BlockId, from: PublicKey) -> bool {
        let now = Instant::now();
        let cmd = Command::Received(id, from, now);

        self.send_command(cmd).await
    }

    /// Get latency information for a given peer
    #[allow(dead_code)]
    pub async fn get_latency(&self, from: PublicKey) -> Option<Duration> {
        let (tx, rx) = oneshot::channel();

        self.send_command(Command::Latency(from, tx)).await;

        rx.await.ok().flatten()
    }

    /// Purge all information related to the given batch
    pub async fn purge(&self, info: BatchInfo) -> bool {
        let cmd = Command::Purge(info);

        self.send_command(cmd).await
    }

    async fn send_command(&self, command: Command) -> bool {
        self.commands.send(command).await.is_ok()
    }
}

impl Default for ProviderHandle {
    fn default() -> Self {
        Self::new(32, Duration::from_secs(1))
    }
}

#[derive(Debug)]
enum Command {
    /// Mark a request as done and update latency
    Received(BlockId, PublicKey, Instant),
    /// Get the best provider for a given block
    Best(BlockId, Instant, oneshot::Sender<Option<PublicKey>>),
    /// Register a new provider for given block
    Register(BlockId, PublicKey),
    /// Get latency information for a peer
    #[allow(dead_code)]
    Latency(PublicKey, oneshot::Sender<Option<Duration>>),
    /// Purge all providers information for specified batch
    Purge(BatchInfo),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Received(id, pkey, now) =>
                    format!("received {} from {} on {:#?}", id, pkey, now),
                Self::Best(id, _, _) => format!("request best for {}", id),
                Self::Purge(info) => format!("purge for {}", info),
                Self::Register(id, prov) => format!("{} as provider for {}", prov, id),
                Self::Latency(key, _) => format!("latency for {}", key),
            }
        )
    }
}

struct ProviderAgent {
    latencies: HashMap<PublicKey, Duration>,
    pending: HashMap<BlockId, (Instant, PublicKey)>,
    providers: BTreeMap<BlockId, Provider>,
    timeout: Duration,
    commands: mpsc::Receiver<Command>,
}

impl ProviderAgent {
    fn new(commands: mpsc::Receiver<Command>, timeout: Duration) -> Self {
        Self {
            pending: Default::default(),
            latencies: Default::default(),
            providers: Default::default(),

            commands,
            timeout,
        }
    }

    fn get_best_for(&self, id: &BlockId) -> Option<PublicKey> {
        self.providers
            .get(&id)
            .map(|providers| {
                self.latencies
                    .iter()
                    .filter(|(key, _)| providers.contains(key))
                    .min_by_key(|(_, lat)| *lat)
                    .map(|(key, _)| *key)
            })
            .flatten()
    }

    fn timed_out(&self, id: &BlockId) -> bool {
        self.pending
            .get(id)
            .map(|(to, _)| {
                if to.elapsed() >= self.timeout {
                    trace!("time out detected for {}", id);
                    true
                } else {
                    false
                }
            })
            .unwrap_or(true)
    }

    fn spawn(mut self) -> JoinHandle<Self> {
        task::spawn(async move {
            while let Some(cmd) = self.commands.recv().await.map(|x| {
                trace!("received command {}", x);
                x
            }) {
                match cmd {
                    Command::Received(id, from, instant) => {
                        if let Entry::Occupied(e) = self.pending.entry(id) {
                            let (to, reg) = *e.get();

                            if reg == from {
                                e.remove_entry();

                                self.latencies.insert(from, instant.duration_since(to));
                            }
                        }

                        self.providers.entry(id).and_modify(|x| x.set_complete());
                    }
                    Command::Latency(from, resp) => {
                        let _ = resp.send(self.latencies.get(&from).copied());
                    }
                    Command::Best(id, date, resp) => {
                        let result = if self.timed_out(&id) {
                            let out = self.get_best_for(&id);
                            if let Some(ref provider) = out {
                                self.pending.insert(id, (date, *provider));
                            }
                            out
                        } else {
                            None
                        };

                        // ignoring errors since this only means receiver is not interested anymore
                        let _ = resp.send(result);
                    }
                    Command::Register(id, from) => {
                        self.providers
                            .entry(id)
                            .and_modify(|set| {
                                if set.insert(from) {
                                    trace!("new provider {} for {}", from, id);
                                }
                            })
                            .or_insert_with(|| from.into());
                        // insert a very high default latency if we don't have information for this peer
                        self.latencies
                            .entry(from)
                            .or_insert_with(|| Duration::from_secs(3600));
                    }
                    Command::Purge(info) => {
                        let digest = *info.digest();
                        let iter = (0..info.sequence()).map(|x| BlockId::new(digest, x));

                        for id in iter {
                            self.pending.remove(&id);
                            self.providers.entry(id).and_modify(|x| x.set_complete());
                        }
                    }
                }
            }

            self
        })
    }
}

enum Provider {
    /// Provider list for an not yet received block
    Pending(HashSet<PublicKey>),
    /// Status for a block that has already been received
    Complete,
}

impl Provider {
    fn contains(&self, key: &PublicKey) -> bool {
        if let Self::Pending(ref set) = self {
            set.contains(key)
        } else {
            false
        }
    }

    fn set_complete(&mut self) {
        *self = Self::Complete
    }

    fn insert(&mut self, key: PublicKey) -> bool {
        if let Self::Pending(ref mut set) = self {
            set.insert(key)
        } else {
            false
        }
    }
}

impl From<PublicKey> for Provider {
    fn from(key: PublicKey) -> Self {
        let mut set = HashSet::default();
        set.insert(key);

        Self::Pending(set)
    }
}

#[cfg(test)]
mod test {
    use super::super::test::generate_batch;
    use super::*;

    use drop::test::keyset;

    async fn fill_handle(
        keys: impl Iterator<Item = &PublicKey>,
        handle: &ProviderHandle,
    ) -> BlockId {
        let batch = generate_batch(1);
        let blockid = BlockId::new(*batch.info().digest(), 0);

        for key in keys {
            assert!(handle.register_provider(blockid, *key).await);
        }

        BlockId::new(*batch.info().digest(), 0)
    }

    #[tokio::test]
    async fn register_providers() {
        let handle = ProviderHandle::default();
        let keys: Vec<_> = keyset(10).collect();

        fill_handle(keys.iter(), &handle).await;
    }

    #[tokio::test]
    async fn get_best_provider() {
        let handle = ProviderHandle::default();
        let keys: Vec<_> = keyset(10).collect();

        let id = fill_handle(keys.iter(), &handle).await;

        let best = handle
            .best_provider(id)
            .await
            .expect("unable to fetch best provider");

        assert!(keys.contains(&best), "bad best provider returned");
    }

    #[tokio::test]
    async fn register_request() {
        let handle = ProviderHandle::default();
        let keys: Vec<_> = keyset(10).collect();

        let id = fill_handle(keys.iter(), &handle).await;

        handle.best_provider(id).await.expect("no provider");

        assert!(
            handle.best_provider(id).await.is_none(),
            "could send two concurrent requests"
        );
    }

    #[tokio::test]
    async fn update_latency() {
        let handle = ProviderHandle::default();
        let keys: Vec<_> = keyset(10).collect();

        let id = fill_handle(keys.iter(), &handle).await;

        let provider = handle.best_provider(id).await.expect("no provider");
        assert!(handle.register_response(id, provider).await);

        assert!(
            handle.get_latency(provider).await.unwrap() < Duration::from_secs(3600),
            "wrong best returned"
        );
    }

    #[tokio::test]
    async fn purge() {
        let handle = ProviderHandle::default();
        let keys: Vec<_> = keyset(10).collect();
        let id = fill_handle(keys.iter(), &handle).await;
        let info = BatchInfo::new(1, *id.digest());

        assert!(handle.purge(info).await);

        let best = handle.best_provider(id).await;

        assert!(best.is_none(), "returned purged data");
    }

    #[tokio::test]
    async fn cant_re_request() {
        use std::iter;

        let handle = ProviderHandle::default();
        let key = keyset(1).next().unwrap();
        let id = fill_handle(iter::once(&key), &handle).await;

        handle.best_provider(id).await.expect("no provider");
        handle.register_response(id, key).await;

        assert!(handle.best_provider(id).await.is_none());
    }
}
