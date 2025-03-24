use std::{
    borrow::Borrow,
    hash::Hash,
    num::NonZeroUsize,
    sync::{LazyLock, RwLock},
};

use lru::LruCache;

use crate::connectors::base::{LockScriptCacheEntry, TaprootSpendInfoCacheEntry};

const DEFAULT_CACHE_SIZE: usize = 1000;
pub(crate) static TAPROOT_SPEND_INFO_CACHE: LazyLock<
    RwLock<Cache<String, TaprootSpendInfoCacheEntry>>,
> = LazyLock::new(|| RwLock::new(Cache::new(DEFAULT_CACHE_SIZE)));
pub(crate) static TAPROOT_LOCK_SCRIPTS_CACHE: LazyLock<
    RwLock<Cache<String, LockScriptCacheEntry>>,
> = LazyLock::new(|| RwLock::new(Cache::new(DEFAULT_CACHE_SIZE)));

pub struct Cache<K: Eq + Hash, V>(LruCache<K, V>);

impl<K, V> Cache<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    fn new(cap: usize) -> Self {
        Self(LruCache::new(NonZeroUsize::new(cap).unwrap()))
    }

    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        self.0.put(key, value)
    }

    pub fn push(&mut self, key: K, value: V) -> Option<(K, V)> {
        self.0.push(key, value)
    }

    pub fn get<Q: ?Sized>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0.get(key)
    }

    pub fn get_or_put<F>(&mut self, key: K, f: F) -> &V
    where
        F: FnOnce() -> V,
    {
        self.0.get_or_insert(key, f)
    }

    pub fn try_get_or_insert<F, E>(&mut self, k: K, f: F) -> Result<&V, E>
    where
        F: FnOnce() -> Result<V, E>,
    {
        self.0.try_get_or_insert(k, f)
    }

    pub fn contains<Q: ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0.contains(key)
    }
}
