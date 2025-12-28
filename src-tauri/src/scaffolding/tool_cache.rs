// Tool Output Cache
//
// Caches results of tool executions to avoid redundant operations.
// Particularly useful for file reads and directory listings.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Configuration for the tool cache
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of cached entries
    pub max_entries: usize,
    /// Default TTL for cached entries
    pub default_ttl: Duration,
    /// Enable caching
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100,
            default_ttl: Duration::from_secs(60), // 1 minute
            enabled: true,
        }
    }
}

/// A cached tool result
#[derive(Debug, Clone)]
struct CacheEntry {
    result: CachedResult,
    created_at: Instant,
    ttl: Duration,
    hit_count: u32,
}

impl CacheEntry {
    fn is_valid(&self) -> bool {
        self.created_at.elapsed() < self.ttl
    }
}

/// Result stored in cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResult {
    pub success: bool,
    pub output: String,
    pub hash: Option<String>,
}

/// Which tools can be cached
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheableTool {
    ReadFile,
    GlobFiles,
    GrepFiles,
    ListDirectory,
}

impl CacheableTool {
    /// Get TTL for this tool type
    fn ttl(&self) -> Duration {
        match self {
            Self::ReadFile => Duration::from_secs(30),     // Files can change
            Self::GlobFiles => Duration::from_secs(60),   // Structure changes less
            Self::GrepFiles => Duration::from_secs(30),   // Content matters
            Self::ListDirectory => Duration::from_secs(60),
        }
    }

    /// Parse tool name into cacheable type
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "read_file" => Some(Self::ReadFile),
            "glob_files" => Some(Self::GlobFiles),
            "grep_files" => Some(Self::GrepFiles),
            "list_directory" => Some(Self::ListDirectory),
            _ => None,
        }
    }
}

/// Manages tool result caching
pub struct ToolCache {
    config: CacheConfig,
    entries: HashMap<String, CacheEntry>,
    stats: CacheStats,
}

/// Cache statistics
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub invalidations: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

impl ToolCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            stats: CacheStats::default(),
        }
    }

    /// Create a cache key from tool name and arguments
    pub fn make_key(tool: &str, args: &serde_json::Value) -> String {
        // Sort args for consistent keys
        let args_str = serde_json::to_string(args).unwrap_or_default();
        format!("{}:{}", tool, args_str)
    }

    /// Check if we have a valid cached result
    pub fn get(&mut self, tool: &str, args: &serde_json::Value) -> Option<CachedResult> {
        if !self.config.enabled {
            return None;
        }

        let key = Self::make_key(tool, args);

        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.is_valid() {
                entry.hit_count += 1;
                self.stats.hits += 1;
                return Some(entry.result.clone());
            } else {
                // Expired
                self.entries.remove(&key);
            }
        }

        self.stats.misses += 1;
        None
    }

    /// Store a result in the cache
    pub fn set(&mut self, tool: &str, args: &serde_json::Value, result: CachedResult) {
        if !self.config.enabled {
            return;
        }

        // Enforce max entries
        if self.entries.len() >= self.config.max_entries {
            self.evict_lru();
        }

        let key = Self::make_key(tool, args);
        let ttl = CacheableTool::from_name(tool)
            .map(|t| t.ttl())
            .unwrap_or(self.config.default_ttl);

        self.entries.insert(key, CacheEntry {
            result,
            created_at: Instant::now(),
            ttl,
            hit_count: 0,
        });
    }

    /// Invalidate cache for a specific file (after write/edit)
    pub fn invalidate_file(&mut self, path: &str) {
        let to_remove: Vec<String> = self.entries.keys()
            .filter(|k| k.contains(path))
            .cloned()
            .collect();

        for key in to_remove {
            self.entries.remove(&key);
            self.stats.invalidations += 1;
        }
    }

    /// Invalidate all entries for a tool type
    pub fn invalidate_tool(&mut self, tool: &str) {
        let prefix = format!("{}:", tool);
        let to_remove: Vec<String> = self.entries.keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();

        for key in to_remove {
            self.entries.remove(&key);
            self.stats.invalidations += 1;
        }
    }

    /// Clear all cache
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Get number of cached entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict least recently used entry
    fn evict_lru(&mut self) {
        // Find entry with oldest access and lowest hit count
        let victim = self.entries.iter()
            .min_by_key(|(_, entry)| (entry.hit_count, entry.created_at))
            .map(|(k, _)| k.clone());

        if let Some(key) = victim {
            self.entries.remove(&key);
            self.stats.evictions += 1;
        }
    }

    /// Remove expired entries
    pub fn cleanup_expired(&mut self) {
        let expired: Vec<String> = self.entries.iter()
            .filter(|(_, entry)| !entry.is_valid())
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            self.entries.remove(&key);
        }
    }
}

impl Default for ToolCache {
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

/// Helper to determine if a tool result should be cached
pub fn should_cache(tool: &str, success: bool) -> bool {
    // Only cache successful results for read-only operations
    if !success {
        return false;
    }

    CacheableTool::from_name(tool).is_some()
}

/// Helper to determine if tool execution should invalidate cache
pub fn invalidates_cache(tool: &str) -> bool {
    matches!(tool, "write_file" | "edit_file" | "execute_shell")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit() {
        let mut cache = ToolCache::new(CacheConfig::default());

        let args = serde_json::json!({"path": "test.rs"});
        let result = CachedResult {
            success: true,
            output: "file contents".to_string(),
            hash: None,
        };

        cache.set("read_file", &args, result.clone());

        let cached = cache.get("read_file", &args);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().output, "file contents");
        assert_eq!(cache.stats.hits, 1);
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = ToolCache::new(CacheConfig::default());

        let args = serde_json::json!({"path": "test.rs"});
        let cached = cache.get("read_file", &args);

        assert!(cached.is_none());
        assert_eq!(cache.stats.misses, 1);
    }

    #[test]
    fn test_invalidation() {
        let mut cache = ToolCache::new(CacheConfig::default());

        let args = serde_json::json!({"path": "test.rs"});
        cache.set("read_file", &args, CachedResult {
            success: true,
            output: "contents".to_string(),
            hash: None,
        });

        assert!(cache.get("read_file", &args).is_some());

        cache.invalidate_file("test.rs");

        assert!(cache.get("read_file", &args).is_none());
        assert_eq!(cache.stats.invalidations, 1);
    }

    #[test]
    fn test_max_entries() {
        let config = CacheConfig {
            max_entries: 2,
            ..Default::default()
        };
        let mut cache = ToolCache::new(config);

        for i in 0..5 {
            let args = serde_json::json!({"path": format!("file{}.rs", i)});
            cache.set("read_file", &args, CachedResult {
                success: true,
                output: format!("content {}", i),
                hash: None,
            });
        }

        assert!(cache.len() <= 2);
        assert!(cache.stats.evictions > 0);
    }

    #[test]
    fn test_cache_key() {
        let args1 = serde_json::json!({"path": "a.rs"});
        let args2 = serde_json::json!({"path": "b.rs"});

        let key1 = ToolCache::make_key("read_file", &args1);
        let key2 = ToolCache::make_key("read_file", &args2);

        assert_ne!(key1, key2);

        // Same args should produce same key
        let key1_again = ToolCache::make_key("read_file", &args1);
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_should_cache() {
        assert!(should_cache("read_file", true));
        assert!(should_cache("glob_files", true));
        assert!(!should_cache("read_file", false)); // Failed
        assert!(!should_cache("write_file", true)); // Write operation
        assert!(!should_cache("execute_shell", true)); // Side effects
    }

    #[test]
    fn test_invalidates_cache() {
        assert!(invalidates_cache("write_file"));
        assert!(invalidates_cache("edit_file"));
        assert!(invalidates_cache("execute_shell"));
        assert!(!invalidates_cache("read_file"));
        assert!(!invalidates_cache("glob_files"));
    }

    #[test]
    fn test_cacheable_tool_ttl() {
        assert!(CacheableTool::ReadFile.ttl() < CacheableTool::GlobFiles.ttl());
    }

    #[test]
    fn test_hit_rate() {
        let mut cache = ToolCache::new(CacheConfig::default());

        // 1 miss
        let args = serde_json::json!({"path": "test.rs"});
        cache.get("read_file", &args);

        // Set and 2 hits
        cache.set("read_file", &args, CachedResult {
            success: true,
            output: "x".to_string(),
            hash: None,
        });
        cache.get("read_file", &args);
        cache.get("read_file", &args);

        // 2 hits, 1 miss = 66.67% hit rate
        let rate = cache.stats.hit_rate();
        assert!(rate > 0.6 && rate < 0.7);
    }

    #[test]
    fn test_disabled_cache() {
        let config = CacheConfig {
            enabled: false,
            ..Default::default()
        };
        let mut cache = ToolCache::new(config);

        let args = serde_json::json!({"path": "test.rs"});
        cache.set("read_file", &args, CachedResult {
            success: true,
            output: "x".to_string(),
            hash: None,
        });

        assert!(cache.get("read_file", &args).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut cache = ToolCache::new(CacheConfig::default());

        let args = serde_json::json!({"path": "test.rs"});
        cache.set("read_file", &args, CachedResult {
            success: true,
            output: "x".to_string(),
            hash: None,
        });

        assert!(!cache.is_empty());
        cache.clear();
        assert!(cache.is_empty());
    }
}
