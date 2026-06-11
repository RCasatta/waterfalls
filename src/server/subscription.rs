use std::collections::{HashMap, HashSet};

use tokio::sync::mpsc;

use crate::ScriptHash;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SubscriptionId(u64);

impl std::fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubscriptionEvent {
    Block,
    Mempool,
    Reorg,
}

impl SubscriptionEvent {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SubscriptionEvent::Block => "block",
            SubscriptionEvent::Mempool => "mempool",
            SubscriptionEvent::Reorg => "reorg",
        }
    }
}

impl std::fmt::Display for SubscriptionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub(crate) type SubscriptionReceiver = mpsc::Receiver<SubscriptionEvent>;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SubscriptionError {
    Empty,
    TooManyScripts,
    TooManySubscriptions,
}

pub(crate) struct Subscriptions {
    next_id: u64,
    max_active: usize,
    max_scripts_per_subscription: usize,
    by_id: HashMap<SubscriptionId, Subscription>,
    by_script: HashMap<ScriptHash, HashSet<SubscriptionId>>,
}

struct Subscription {
    scripts: Vec<ScriptHash>,
    sender: mpsc::Sender<SubscriptionEvent>,
}

impl Subscriptions {
    pub(crate) fn new(max_active: usize, max_scripts_per_subscription: usize) -> Self {
        Self {
            next_id: 0,
            max_active,
            max_scripts_per_subscription,
            by_id: HashMap::new(),
            by_script: HashMap::new(),
        }
    }

    pub(crate) fn subscribe(
        &mut self,
        scripts: Vec<ScriptHash>,
    ) -> Result<(SubscriptionId, SubscriptionReceiver), SubscriptionError> {
        if self.by_id.len() >= self.max_active {
            return Err(SubscriptionError::TooManySubscriptions);
        }

        let scripts = deduplicate(scripts);
        if scripts.is_empty() {
            return Err(SubscriptionError::Empty);
        }
        if scripts.len() > self.max_scripts_per_subscription {
            return Err(SubscriptionError::TooManyScripts);
        }

        let id = SubscriptionId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);

        let (sender, receiver) = mpsc::channel(1);
        for script in scripts.iter().copied() {
            self.by_script.entry(script).or_default().insert(id);
        }
        let scripts_len = scripts.len();
        self.by_id.insert(id, Subscription { scripts, sender });
        log::info!(
            "subscription registered: id={id}, scripts={scripts_len}, active={}",
            self.by_id.len()
        );

        Ok((id, receiver))
    }

    pub(crate) fn unsubscribe(&mut self, id: SubscriptionId) -> bool {
        let Some(subscription) = self.by_id.remove(&id) else {
            return false;
        };

        let scripts_len = subscription.scripts.len();
        for script in subscription.scripts {
            if let Some(ids) = self.by_script.get_mut(&script) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.by_script.remove(&script);
                }
            }
        }
        log::info!(
            "subscription closed: id={id}, scripts={scripts_len}, active={}",
            self.by_id.len()
        );

        true
    }

    pub(crate) fn notify_scripts<I>(&mut self, event: SubscriptionEvent, scripts: I) -> usize
    where
        I: IntoIterator<Item = ScriptHash>,
    {
        let mut subscriptions = HashSet::new();
        for script in scripts {
            if let Some(ids) = self.by_script.get(&script) {
                subscriptions.extend(ids.iter().copied());
            }
        }

        self.notify_subscriptions(event, subscriptions)
    }

    pub(crate) fn notify_all(&mut self, event: SubscriptionEvent) -> usize {
        let subscriptions = self.by_id.keys().copied().collect();
        self.notify_subscriptions(event, subscriptions)
    }

    fn notify_subscriptions(
        &mut self,
        event: SubscriptionEvent,
        subscriptions: HashSet<SubscriptionId>,
    ) -> usize {
        let mut sent = 0;
        let mut coalesced = 0;
        let mut closed = Vec::new();

        for id in subscriptions {
            let Some(subscription) = self.by_id.get(&id) else {
                continue;
            };
            match subscription.sender.try_send(event) {
                Ok(()) => {
                    sent += 1;
                    crate::inc_subscription_notification_counter(event.as_str(), "queued");
                    log::info!("subscription notification queued: id={id}, event={event}");
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    coalesced += 1;
                    crate::inc_subscription_notification_counter(event.as_str(), "coalesced");
                    log::info!("subscription notification coalesced: id={id}, event={event}");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    crate::inc_subscription_notification_counter(event.as_str(), "closed");
                    closed.push(id);
                }
            }
        }

        if sent > 0 || coalesced > 0 || !closed.is_empty() {
            log::info!(
                "subscription notify summary: event={event}, sent={sent}, coalesced={coalesced}, closed={}",
                closed.len()
            );
        }

        for id in closed {
            self.unsubscribe(id);
        }

        sent
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_id.len()
    }
}

fn deduplicate(scripts: Vec<ScriptHash>) -> Vec<ScriptHash> {
    let mut seen = HashSet::new();
    scripts
        .into_iter()
        .filter(|script| seen.insert(*script))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_rejects_empty_and_too_many_scripts() {
        let mut subscriptions = Subscriptions::new(10, 2);

        assert_eq!(
            subscriptions.subscribe(Vec::new()).unwrap_err(),
            SubscriptionError::Empty
        );
        assert_eq!(
            subscriptions.subscribe(vec![1, 2, 3]).unwrap_err(),
            SubscriptionError::TooManyScripts
        );
    }

    #[test]
    fn subscribe_rejects_too_many_subscriptions() {
        let mut subscriptions = Subscriptions::new(1, 10);

        subscriptions.subscribe(vec![1]).unwrap();

        assert_eq!(
            subscriptions.subscribe(vec![2]).unwrap_err(),
            SubscriptionError::TooManySubscriptions
        );
    }

    #[test]
    fn notify_scripts_fans_out_once_per_subscription() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_first_id, mut first_rx) = subscriptions.subscribe(vec![1, 2]).unwrap();
        let (_second_id, mut second_rx) = subscriptions.subscribe(vec![2, 3]).unwrap();

        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Block, vec![1, 2]),
            2
        );

        assert_eq!(first_rx.try_recv().unwrap(), SubscriptionEvent::Block);
        assert_eq!(second_rx.try_recv().unwrap(), SubscriptionEvent::Block);
        assert!(first_rx.try_recv().is_err());
        assert!(second_rx.try_recv().is_err());
    }

    #[test]
    fn notify_scripts_coalesces_when_receiver_is_full() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_id, mut rx) = subscriptions.subscribe(vec![1]).unwrap();

        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Block, vec![1]),
            1
        );
        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Mempool, vec![1]),
            0
        );

        assert_eq!(rx.try_recv().unwrap(), SubscriptionEvent::Block);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn unsubscribe_removes_script_index_entries() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (id, mut rx) = subscriptions.subscribe(vec![1, 2]).unwrap();

        assert!(subscriptions.unsubscribe(id));
        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Block, vec![1, 2]),
            0
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(subscriptions.len(), 0);
    }

    #[test]
    fn closed_receivers_are_pruned_on_notify() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_id, rx) = subscriptions.subscribe(vec![1]).unwrap();
        drop(rx);

        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Block, vec![1]),
            0
        );

        assert_eq!(subscriptions.len(), 0);
    }

    #[test]
    fn notify_all_sends_reorg_to_every_subscription() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_first_id, mut first_rx) = subscriptions.subscribe(vec![1]).unwrap();
        let (_second_id, mut second_rx) = subscriptions.subscribe(vec![2]).unwrap();

        assert_eq!(subscriptions.notify_all(SubscriptionEvent::Reorg), 2);

        assert_eq!(first_rx.try_recv().unwrap(), SubscriptionEvent::Reorg);
        assert_eq!(second_rx.try_recv().unwrap(), SubscriptionEvent::Reorg);
    }
}
