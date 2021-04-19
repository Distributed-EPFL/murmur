use super::*;

use tokio::sync::oneshot;
use tokio::task;

enum Command<M>
where
    M: Message,
{
    /// Add a new payload to the Sponge
    Collect(Payload<M>, oneshot::Sender<Option<Batch<M>>>),
    /// Collect without completing batch,
    CollectOnly(Payload<M>),
    /// Force batch creation when delay has expired
    ForceBatch(oneshot::Sender<Option<Batch<M>>>),
}

#[derive(Clone)]
pub struct SpongeHandle<M>
where
    M: Message,
{
    tx: mpsc::Sender<Command<M>>,
}

impl<M> SpongeHandle<M>
where
    M: Message + 'static,
{
    pub fn new(cap: usize, threshold: usize, block_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(cap);

        let agent = SpongeAgent::new(Sponge::default(), block_size, rx);

        agent.spawn(threshold);

        Self { tx }
    }

    /// Collect a `Payload` and produce a `Batch` if the threshold was reached
    pub async fn collect(&self, payload: Payload<M>) -> Option<Batch<M>> {
        let (tx, rx) = oneshot::channel();

        self.tx.send(Command::Collect(payload, tx)).await.ok()?;

        rx.await.ok().flatten()
    }

    /// Only collect a `Payload` without creating a `Batch`
    pub async fn collect_only(&self, payload: Payload<M>) {
        let _ = self.tx.send(Command::CollectOnly(payload)).await;
    }

    /// Force `Batch` creation, usually if the delay was exceeded
    pub async fn force(&self) -> Option<Batch<M>> {
        let (tx, rx) = oneshot::channel();

        let _ = self.tx.send(Command::ForceBatch(tx)).await;

        rx.await.ok().flatten()
    }
}

struct SpongeAgent<M>
where
    M: Message,
{
    sponge: Sponge<M>,
    block_size: usize,
    rx: mpsc::Receiver<Command<M>>,
}

impl<M> SpongeAgent<M>
where
    M: Message + 'static,
{
    fn new(sponge: Sponge<M>, block_size: usize, rx: mpsc::Receiver<Command<M>>) -> Self {
        Self {
            sponge,
            block_size,
            rx,
        }
    }

    fn spawn(mut self, threshold: usize) {
        task::spawn(async move {
            while let Some(command) = self.rx.recv().await {
                match command {
                    Command::Collect(payload, tx) => {
                        self.sponge.insert(payload);

                        trace!(
                            "collected payload, batch completion {}/{}",
                            self.sponge.len(),
                            threshold
                        );

                        let batch = if self.sponge.len() >= threshold {
                            debug!("sponge threshold reached, creating batch...");

                            self.make_batch().await
                        } else {
                            None
                        };

                        let _ = tx.send(batch);
                    }
                    Command::CollectOnly(payload) => {
                        trace!(
                            "collected payload, batch completion {}/{}",
                            self.sponge.len(),
                            threshold
                        );
                        self.sponge.insert(payload);
                    }
                    Command::ForceBatch(tx) => {
                        let batch = if !self.sponge.is_empty() {
                            self.make_batch().await
                        } else {
                            None
                        };

                        let _ = tx.send(batch);
                    }
                }
            }
        });
    }

    async fn make_batch(&mut self) -> Option<Batch<M>> {
        let payloads = self.sponge.take();
        let block_size = self.block_size;

        task::spawn_blocking(move || Sponge::make_batch(payloads, block_size))
            .await
            .ok()
    }
}
