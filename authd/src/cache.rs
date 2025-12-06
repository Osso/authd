use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Cache key: (uid, target)
type CacheKey = (u32, PathBuf);

#[derive(Debug)]
struct CacheEntry {
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct AuthCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
}

impl AuthCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if user has valid cached auth for target
    pub fn is_valid(&self, uid: u32, target: &PathBuf) -> bool {
        let key = (uid, target.clone());
        self.entries
            .read()
            .unwrap()
            .get(&key)
            .is_some_and(|e| e.expires_at > Instant::now())
    }

    /// Cache successful auth for user+target
    pub fn insert(&self, uid: u32, target: PathBuf, timeout_secs: u64) {
        let key = (uid, target);
        let entry = CacheEntry {
            expires_at: Instant::now() + Duration::from_secs(timeout_secs),
        };
        self.entries.write().unwrap().insert(key, entry);
    }

    /// Remove expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.entries.write().unwrap().retain(|_, e| e.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_insert_and_check() {
        let cache = AuthCache::new();
        let target = PathBuf::from("/usr/bin/test");

        assert!(!cache.is_valid(1000, &target));

        cache.insert(1000, target.clone(), 60);

        assert!(cache.is_valid(1000, &target));
        assert!(!cache.is_valid(1001, &target)); // different user
    }

    #[test]
    fn cache_different_targets() {
        let cache = AuthCache::new();
        let target1 = PathBuf::from("/usr/bin/test1");
        let target2 = PathBuf::from("/usr/bin/test2");

        cache.insert(1000, target1.clone(), 60);

        assert!(cache.is_valid(1000, &target1));
        assert!(!cache.is_valid(1000, &target2));
    }

    #[test]
    fn cache_expiry() {
        let cache = AuthCache::new();
        let target = PathBuf::from("/usr/bin/test");

        // Insert with 0 second timeout (already expired)
        cache.insert(1000, target.clone(), 0);

        // Should be invalid immediately
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(!cache.is_valid(1000, &target));
    }

    #[test]
    fn cache_cleanup() {
        let cache = AuthCache::new();
        let target1 = PathBuf::from("/usr/bin/test1");
        let target2 = PathBuf::from("/usr/bin/test2");

        cache.insert(1000, target1.clone(), 0); // expires immediately
        cache.insert(1000, target2.clone(), 60); // valid

        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.cleanup();

        assert!(!cache.is_valid(1000, &target1));
        assert!(cache.is_valid(1000, &target2));
    }
}
