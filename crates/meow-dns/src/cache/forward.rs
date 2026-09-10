use super::CacheEntry;
use lru::LruCache;
use std::sync::Arc;

/// Adaptive replacement balances recently used and frequently used entries.
/// Ghost lists retain keys, never expired DNS answers, and tune the balance
/// when an evicted key is requested again (Megiddo/Modha, FAST 2003).
pub(super) struct ForwardCache {
    recent: LruCache<Arc<str>, CacheEntry>,
    arc: Option<History>,
    capacity: usize,
}

struct History {
    frequent: LruCache<Arc<str>, CacheEntry>,
    recent_ghost: LruCache<Arc<str>, ()>,
    frequent_ghost: LruCache<Arc<str>, ()>,
    recent_target: usize,
}

impl ForwardCache {
    pub fn new(capacity: usize, adaptive: bool) -> Self {
        Self {
            recent: LruCache::unbounded(),
            capacity,
            arc: adaptive.then(|| History {
                frequent: LruCache::unbounded(),
                recent_ghost: LruCache::unbounded(),
                frequent_ghost: LruCache::unbounded(),
                recent_target: 0,
            }),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<&CacheEntry> {
        let Some(history) = &mut self.arc else {
            return self.recent.get(key);
        };
        if let Some((key, value)) = self.recent.pop_entry(key) {
            history.frequent.put(key, value);
        }
        history.frequent.get(key)
    }

    pub fn put(&mut self, key: Arc<str>, value: CacheEntry) {
        let Some(h) = &mut self.arc else {
            self.recent.put(key, value);
            if self.recent.len() > self.capacity {
                self.recent.pop_lru();
            }
            return;
        };
        if self.recent.pop(key.as_ref()).is_some() || h.frequent.contains(key.as_ref()) {
            h.frequent.put(key, value);
            return;
        }
        let in_recent = h.recent_ghost.contains(key.as_ref());
        let in_frequent = h.frequent_ghost.contains(key.as_ref());
        if in_recent || in_frequent {
            if in_recent {
                let step = (h.frequent_ghost.len() / h.recent_ghost.len()).max(1);
                h.recent_target = (h.recent_target + step).min(self.capacity);
            } else {
                let step = (h.recent_ghost.len() / h.frequent_ghost.len()).max(1);
                h.recent_target = h.recent_target.saturating_sub(step);
            }
            if self.recent.len() + h.frequent.len() >= self.capacity {
                Self::replace(&mut self.recent, h, in_frequent);
            }
            h.recent_ghost.pop(key.as_ref());
            h.frequent_ghost.pop(key.as_ref());
            h.frequent.put(key, value);
            return;
        }

        if self.recent.len() + h.recent_ghost.len() == self.capacity {
            if self.recent.len() == self.capacity {
                self.recent.pop_lru();
            } else {
                h.recent_ghost.pop_lru();
                Self::replace(&mut self.recent, h, false);
            }
        } else {
            let total = self.recent.len()
                + h.frequent.len()
                + h.recent_ghost.len()
                + h.frequent_ghost.len();
            if total >= self.capacity {
                if total == 2 * self.capacity {
                    h.frequent_ghost.pop_lru();
                }
                if self.recent.len() + h.frequent.len() >= self.capacity {
                    Self::replace(&mut self.recent, h, false);
                }
            }
        }
        self.recent.put(key, value);
    }

    fn replace(recent: &mut LruCache<Arc<str>, CacheEntry>, h: &mut History, frequent_hit: bool) {
        if !recent.is_empty()
            && (recent.len() > h.recent_target
                || frequent_hit && recent.len() == h.recent_target
                || h.frequent.is_empty())
        {
            if let Some((key, _)) = recent.pop_lru() {
                h.recent_ghost.put(key, ());
            }
        } else if let Some((key, _)) = h.frequent.pop_lru() {
            h.frequent_ghost.put(key, ());
        }
    }

    pub fn pop(&mut self, key: &str) {
        self.recent.pop(key);
        if let Some(h) = &mut self.arc {
            h.frequent.pop(key);
            h.recent_ghost.pop(key);
            h.frequent_ghost.pop(key);
        }
    }

    pub fn len(&self) -> usize {
        self.recent.len() + self.arc.as_ref().map_or(0, |h| h.frequent.len())
    }

    pub fn clear(&mut self) {
        *self = Self::new(self.capacity, self.arc.is_some());
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Arc<str>, &CacheEntry)> {
        self.recent
            .iter()
            .chain(self.arc.iter().flat_map(|h| h.frequent.iter()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{NegKind, QueryFamilies};
    use std::time::Instant;

    fn answer() -> CacheEntry {
        CacheEntry {
            ips: Box::new([]),
            expire_v4: Instant::now(),
            expire_v6: Instant::now(),
            source: None,
            queried: QueryFamilies::IPV4,
            neg: NegKind::empty(),
        }
    }

    #[test]
    fn a_scan_preserves_frequently_requested_answers() {
        let mut arc = ForwardCache::new(4, true);
        let mut lru = ForwardCache::new(4, false);
        for cache in [&mut arc, &mut lru] {
            cache.put(Arc::from("hot"), answer());
            assert!(cache.get("hot").is_some());
            for i in 0..20 {
                cache.put(Arc::from(format!("scan-{i}")), answer());
            }
        }
        assert!(arc.get("hot").is_some());
        assert!(lru.get("hot").is_none());
        assert_eq!(arc.len(), 4);
    }

    #[test]
    fn ghost_hits_adapt_and_never_expose_evicted_answers() {
        let mut cache = ForwardCache::new(2, true);
        cache.put(Arc::from("hot"), answer());
        cache.get("hot");
        cache.put(Arc::from("a"), answer());
        cache.put(Arc::from("b"), answer());
        assert!(cache.get("a").is_none());
        cache.put(Arc::from("a"), answer());
        assert_eq!(cache.arc.as_ref().unwrap().recent_target, 1);
        assert!(cache.get("hot").is_none());
        cache.put(Arc::from("hot"), answer());
        assert_eq!(cache.arc.as_ref().unwrap().recent_target, 0);
        assert!(cache.get("hot").is_some());
    }

    #[test]
    fn churn_and_expiration_keep_both_resident_and_ghost_storage_bounded() {
        let mut cache = ForwardCache::new(8, true);
        let mut seed = 42u64;
        for _ in 0..20_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let key = (seed >> 32 & 31).to_string();
            match seed >> 60 {
                0..=2 => cache.pop(&key),
                3..=8 => {
                    cache.get(&key);
                }
                _ => cache.put(Arc::from(key), answer()),
            }
            let h = cache.arc.as_ref().unwrap();
            assert!(cache.len() <= 8);
            assert!(cache.recent.len() + h.recent_ghost.len() <= 8);
            assert!(cache.len() + h.recent_ghost.len() + h.frequent_ghost.len() <= 16);
            let keys: Vec<_> = cache
                .iter()
                .map(|(key, _)| key.as_ref())
                .chain(h.recent_ghost.iter().map(|(key, _)| key.as_ref()))
                .chain(h.frequent_ghost.iter().map(|(key, _)| key.as_ref()))
                .collect();
            assert_eq!(
                keys.len(),
                keys.iter().collect::<std::collections::HashSet<_>>().len()
            );
        }
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.arc.as_ref().unwrap().recent_target, 0);
    }
}
