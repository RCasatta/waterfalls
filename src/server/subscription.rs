use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use tokio::sync::Notify;

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
    Tip,
    Block,
    Mempool,
    Reorg,
}

impl SubscriptionEvent {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SubscriptionEvent::Tip => "tip",
            SubscriptionEvent::Block => "block",
            SubscriptionEvent::Mempool => "mempool",
            SubscriptionEvent::Reorg => "reorg",
        }
    }

    fn priority(self) -> u8 {
        match self {
            SubscriptionEvent::Tip => 0,
            SubscriptionEvent::Mempool => 1,
            SubscriptionEvent::Block => 2,
            SubscriptionEvent::Reorg => 3,
        }
    }

    fn merge(self, incoming: SubscriptionEvent) -> SubscriptionEvent {
        if incoming.priority() > self.priority() {
            incoming
        } else {
            self
        }
    }
}

impl std::fmt::Display for SubscriptionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub(crate) struct SubscriptionReceiver {
    queue: Arc<SubscriptionQueue>,
}

impl std::fmt::Debug for SubscriptionReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionReceiver")
            .finish_non_exhaustive()
    }
}

impl SubscriptionReceiver {
    pub(crate) async fn recv(&mut self) -> Option<SubscriptionEvent> {
        loop {
            let notified = self.queue.notify.notified();
            if let Some(event) = self.queue.take() {
                return Some(event);
            }
            notified.await;
        }
    }

    #[cfg(test)]
    fn try_recv(&mut self) -> Result<SubscriptionEvent, ()> {
        self.queue.take().ok_or(())
    }
}

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
    by_descriptor: HashMap<u64, HashSet<SubscriptionId>>,
}

struct Subscription {
    scripts: Vec<ScriptHash>,
    /// Number of derivation indexes watched, starting from 0, for each wildcard single descriptor id.
    descriptors: HashMap<u64, u32>,
    queue: Arc<SubscriptionQueue>,
}

struct SubscriptionQueue {
    pending: Mutex<Option<SubscriptionEvent>>,
    notify: Notify,
}

impl SubscriptionQueue {
    fn new() -> Self {
        Self {
            pending: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    fn push(&self, event: SubscriptionEvent) -> PushResult {
        let mut pending = self
            .pending
            .lock()
            .expect("subscription pending event mutex poisoned");
        let result = match *pending {
            Some(existing) => {
                *pending = Some(existing.merge(event));
                PushResult::Coalesced
            }
            None => {
                *pending = Some(event);
                PushResult::Queued
            }
        };
        drop(pending);
        self.notify.notify_one();
        result
    }

    fn take(&self) -> Option<SubscriptionEvent> {
        self.pending
            .lock()
            .expect("subscription pending event mutex poisoned")
            .take()
    }
}

enum PushResult {
    Queued,
    Coalesced,
}

impl Subscriptions {
    pub(crate) fn new(max_active: usize, max_scripts_per_subscription: usize) -> Self {
        Self {
            next_id: 0,
            max_active,
            max_scripts_per_subscription,
            by_id: HashMap::new(),
            by_script: HashMap::new(),
            by_descriptor: HashMap::new(),
        }
    }

    /// `descriptors` maps each wildcard single descriptor id to the number of derivation indexes
    /// watched starting from 0; they are used to later expand the subscription with [`Self::expand`].
    pub(crate) fn subscribe(
        &mut self,
        scripts: Vec<ScriptHash>,
        descriptors: HashMap<u64, u32>,
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

        let queue = Arc::new(SubscriptionQueue::new());
        let receiver = SubscriptionReceiver {
            queue: queue.clone(),
        };
        for script in scripts.iter().copied() {
            self.by_script.entry(script).or_default().insert(id);
        }
        for descriptor_id in descriptors.keys().copied() {
            self.by_descriptor
                .entry(descriptor_id)
                .or_default()
                .insert(id);
        }
        let scripts_len = scripts.len();
        self.by_id.insert(
            id,
            Subscription {
                scripts,
                descriptors,
                queue,
            },
        );
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

        for descriptor_id in subscription.descriptors.keys() {
            if let Some(ids) = self.by_descriptor.get_mut(descriptor_id) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.by_descriptor.remove(descriptor_id);
                }
            }
        }
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

    /// Returns the derivation range `[start, end)` that must be derived to let every subscription
    /// watching `descriptor_id` cover `watch_count` indexes, or `None` if they already do.
    /// Subscriptions at the per-subscription script limit are ignored, and `end` does not exceed
    /// what the subscriptions still have room for, so no derivation work is wasted.
    pub(crate) fn expansion_range(
        &self,
        descriptor_id: u64,
        watch_count: u32,
    ) -> Option<(u32, u32)> {
        let mut range: Option<(u32, u32)> = None;
        for id in self.by_descriptor.get(&descriptor_id)? {
            let Some(subscription) = self.by_id.get(id) else {
                continue;
            };
            let Some(watched) = subscription.descriptors.get(&descriptor_id).copied() else {
                continue;
            };
            let available = self
                .max_scripts_per_subscription
                .saturating_sub(subscription.scripts.len());
            let end = watched
                .saturating_add(u32::try_from(available).unwrap_or(u32::MAX))
                .min(watch_count);
            if watched >= end {
                continue;
            }
            range = Some(match range {
                Some((start, max_end)) => (start.min(watched), max_end.max(end)),
                None => (watched, end),
            });
        }
        range
    }

    /// Extends the subscriptions watching `descriptor_id` with `scripts`, which are the script
    /// hashes for derivation indexes starting at `start`. Returns the number of expanded subscriptions.
    pub(crate) fn expand(
        &mut self,
        descriptor_id: u64,
        start: u32,
        scripts: &[ScriptHash],
    ) -> usize {
        let Some(ids) = self.by_descriptor.get(&descriptor_id) else {
            return 0;
        };
        let end = start + scripts.len() as u32;
        let mut expanded = 0;
        for id in ids.iter().copied() {
            let Some(subscription) = self.by_id.get_mut(&id) else {
                continue;
            };
            let Some(watched) = subscription.descriptors.get_mut(&descriptor_id) else {
                continue;
            };
            // A subscription watching less than `start` would leave a hole, it's expanded
            // on a later call when `start` is computed including it.
            if *watched < start || *watched >= end {
                continue;
            }
            let available = self
                .max_scripts_per_subscription
                .saturating_sub(subscription.scripts.len());
            if available == 0 {
                continue;
            }
            let missing = &scripts[(*watched - start) as usize..];
            if missing.len() > available {
                log::warn!(
                    "subscription expansion truncated, script limit reached: id={id}, limit={}",
                    self.max_scripts_per_subscription
                );
            }
            let new_scripts: Vec<_> = missing.iter().copied().take(available).collect();
            *watched += new_scripts.len() as u32;
            for script in new_scripts.iter().copied() {
                self.by_script.entry(script).or_default().insert(id);
            }
            subscription.scripts.extend(new_scripts);
            expanded += 1;
            log::info!(
                "subscription expanded: id={id}, watched_indexes={}, scripts={}",
                *watched,
                subscription.scripts.len()
            );
        }
        expanded
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

    pub(crate) fn notify_block_tip<I>(&mut self, scripts: I) -> usize
    where
        I: IntoIterator<Item = ScriptHash>,
    {
        let mut block_subscriptions = HashSet::new();
        for script in scripts {
            if let Some(ids) = self.by_script.get(&script) {
                block_subscriptions.extend(ids.iter().copied());
            }
        }

        let tip_subscriptions = self
            .by_id
            .keys()
            .copied()
            .filter(|id| !block_subscriptions.contains(id))
            .collect();

        let block_sent = self.notify_subscriptions(SubscriptionEvent::Block, block_subscriptions);
        let tip_sent = self.notify_subscriptions(SubscriptionEvent::Tip, tip_subscriptions);
        block_sent + tip_sent
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
            if Arc::strong_count(&subscription.queue) == 1 {
                crate::inc_subscription_notification_counter(event.as_str(), "closed");
                closed.push(id);
                continue;
            }

            match subscription.queue.push(event) {
                PushResult::Queued => {
                    sent += 1;
                    crate::inc_subscription_notification_counter(event.as_str(), "queued");
                    log::info!("subscription notification queued: id={id}, event={event}");
                }
                PushResult::Coalesced => {
                    coalesced += 1;
                    crate::inc_subscription_notification_counter(event.as_str(), "coalesced");
                    log::info!("subscription notification coalesced: id={id}, event={event}");
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
            subscriptions
                .subscribe(Vec::new(), HashMap::new())
                .unwrap_err(),
            SubscriptionError::Empty
        );
        assert_eq!(
            subscriptions
                .subscribe(vec![1, 2, 3], HashMap::new())
                .unwrap_err(),
            SubscriptionError::TooManyScripts
        );
    }

    #[test]
    fn subscribe_rejects_too_many_subscriptions() {
        let mut subscriptions = Subscriptions::new(1, 10);

        subscriptions.subscribe(vec![1], HashMap::new()).unwrap();

        assert_eq!(
            subscriptions
                .subscribe(vec![2], HashMap::new())
                .unwrap_err(),
            SubscriptionError::TooManySubscriptions
        );
    }

    #[test]
    fn notify_scripts_fans_out_once_per_subscription() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_first_id, mut first_rx) =
            subscriptions.subscribe(vec![1, 2], HashMap::new()).unwrap();
        let (_second_id, mut second_rx) =
            subscriptions.subscribe(vec![2, 3], HashMap::new()).unwrap();

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
        let (_id, mut rx) = subscriptions.subscribe(vec![1], HashMap::new()).unwrap();

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
    fn notify_scripts_coalesces_to_highest_priority_event() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_id, mut rx) = subscriptions.subscribe(vec![1], HashMap::new()).unwrap();

        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Tip, vec![1]),
            1
        );
        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Block, vec![1]),
            0
        );
        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Tip, vec![1]),
            0
        );

        assert_eq!(rx.try_recv().unwrap(), SubscriptionEvent::Block);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn notify_block_tip_sends_block_or_tip_once_per_subscription() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_first_id, mut first_rx) =
            subscriptions.subscribe(vec![1, 2], HashMap::new()).unwrap();
        let (_second_id, mut second_rx) = subscriptions.subscribe(vec![3], HashMap::new()).unwrap();

        assert_eq!(subscriptions.notify_block_tip(vec![2]), 2);

        assert_eq!(first_rx.try_recv().unwrap(), SubscriptionEvent::Block);
        assert_eq!(second_rx.try_recv().unwrap(), SubscriptionEvent::Tip);
        assert!(first_rx.try_recv().is_err());
        assert!(second_rx.try_recv().is_err());
    }

    #[test]
    fn unsubscribe_removes_script_index_entries() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (id, mut rx) = subscriptions.subscribe(vec![1, 2], HashMap::new()).unwrap();

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
        let (_id, rx) = subscriptions.subscribe(vec![1], HashMap::new()).unwrap();
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
        let (_first_id, mut first_rx) = subscriptions.subscribe(vec![1], HashMap::new()).unwrap();
        let (_second_id, mut second_rx) = subscriptions.subscribe(vec![2], HashMap::new()).unwrap();

        assert_eq!(subscriptions.notify_all(SubscriptionEvent::Reorg), 2);

        assert_eq!(first_rx.try_recv().unwrap(), SubscriptionEvent::Reorg);
        assert_eq!(second_rx.try_recv().unwrap(), SubscriptionEvent::Reorg);
    }

    #[test]
    fn expand_extends_descriptor_subscriptions() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_first_id, mut first_rx) = subscriptions
            .subscribe(vec![10, 11], HashMap::from([(7, 2)]))
            .unwrap();
        let (_second_id, mut second_rx) = subscriptions
            .subscribe(vec![10, 11, 12], HashMap::from([(7, 3)]))
            .unwrap();
        let (_third_id, mut third_rx) = subscriptions.subscribe(vec![10], HashMap::new()).unwrap();

        assert_eq!(subscriptions.expansion_range(7, 2), None);
        assert_eq!(subscriptions.expansion_range(8, 5), None);
        assert_eq!(subscriptions.expansion_range(7, 5), Some((2, 5)));
        assert_eq!(subscriptions.expand(7, 2, &[12, 13, 14]), 2);
        assert_eq!(subscriptions.expansion_range(7, 5), None);

        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Mempool, vec![14]),
            2
        );
        assert_eq!(first_rx.try_recv().unwrap(), SubscriptionEvent::Mempool);
        assert_eq!(second_rx.try_recv().unwrap(), SubscriptionEvent::Mempool);
        assert!(third_rx.try_recv().is_err());
    }

    #[test]
    fn expand_skips_subscriptions_that_would_leave_a_hole() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (_id, mut rx) = subscriptions
            .subscribe(vec![10], HashMap::from([(7, 1)]))
            .unwrap();

        assert_eq!(subscriptions.expand(7, 2, &[12, 13]), 0);
        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Mempool, vec![12]),
            0
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn expand_respects_script_limit() {
        let mut subscriptions = Subscriptions::new(10, 3);
        let (_id, mut rx) = subscriptions
            .subscribe(vec![10, 11], HashMap::from([(7, 2)]))
            .unwrap();

        assert_eq!(subscriptions.expansion_range(7, 10), Some((2, 3)));
        assert_eq!(subscriptions.expand(7, 2, &[12, 13]), 1);
        assert_eq!(subscriptions.expansion_range(7, 10), None);
        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Mempool, vec![13]),
            0
        );
        assert_eq!(
            subscriptions.notify_scripts(SubscriptionEvent::Mempool, vec![12]),
            1
        );
        assert_eq!(rx.try_recv().unwrap(), SubscriptionEvent::Mempool);
    }

    #[test]
    fn expansion_range_ignores_full_subscriptions() {
        let mut subscriptions = Subscriptions::new(10, 4);
        // Full because of scripts of another descriptor
        let (_full_id, _full_rx) = subscriptions
            .subscribe(vec![10, 20, 21, 22], HashMap::from([(7, 1), (8, 3)]))
            .unwrap();

        assert_eq!(subscriptions.expansion_range(7, 10), None);

        let (_id, _rx) = subscriptions
            .subscribe(vec![10, 11], HashMap::from([(7, 2)]))
            .unwrap();

        assert_eq!(subscriptions.expansion_range(7, 10), Some((2, 4)));
    }

    #[test]
    fn unsubscribe_removes_descriptor_index_entries() {
        let mut subscriptions = Subscriptions::new(10, 10);
        let (id, _rx) = subscriptions
            .subscribe(vec![10], HashMap::from([(7, 1)]))
            .unwrap();

        assert!(subscriptions.unsubscribe(id));
        assert_eq!(subscriptions.expansion_range(7, 5), None);
        assert!(subscriptions.by_descriptor.is_empty());
    }
}
