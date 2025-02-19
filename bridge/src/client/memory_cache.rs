use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    sync::{LazyLock, RwLock},
};

use crate::connectors::base::TaprootSpendInfoCache;

const DEFAULT_CACHE_SIZE: usize = 200;
pub(crate) static TAPROOT_SPEND_INFO_CACHE: LazyLock<RwLock<Cache<String, TaprootSpendInfoCache>>> =
    LazyLock::new(|| RwLock::new(Cache::new(DEFAULT_CACHE_SIZE)));

pub struct Cache<K: Eq + Hash, V>(HashMap<K, V>);

impl<K, V> Cache<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    fn new(capacity: usize) -> Self { Self(HashMap::with_capacity(capacity)) }

    pub fn push(&mut self, key: K, value: V) -> Option<V> { self.0.insert(key, value) }

    pub fn get<Q: ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0.get(key)
    }

    pub fn contains<Q: ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0.contains_key(key)
    }
}
