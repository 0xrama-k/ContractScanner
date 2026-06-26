//! In-process abuse prevention (Section 15): a per-IP sliding-window rate limit
//! and a global concurrency semaphore. A shared store (e.g. Redis) for
//! multi-instance deployments is a Future item.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

pub struct RateLimited {
    pub retry_after_secs: u64,
}

pub struct Limiter {
    per_window: u32,
    window: Duration,
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
    sem: Arc<Semaphore>,
}

impl Limiter {
    pub fn new(per_hour: u32, max_concurrent: usize) -> Self {
        Self {
            per_window: per_hour.max(1),
            window: Duration::from_secs(3600),
            hits: Mutex::new(HashMap::new()),
            sem: Arc::new(Semaphore::new(max_concurrent.max(1))),
        }
    }

    /// Record a hit for `key` if under the per-window limit; otherwise reject with
    /// a retry-after hint. Old entries outside the window are pruned on access.
    pub fn check_and_record(&self, key: &str) -> Result<(), RateLimited> {
        let now = Instant::now();
        let mut map = self.hits.lock().expect("rate limiter mutex poisoned");
        let dq = map.entry(key.to_string()).or_default();

        while let Some(front) = dq.front() {
            if now.duration_since(*front) >= self.window {
                dq.pop_front();
            } else {
                break;
            }
        }

        if dq.len() as u32 >= self.per_window {
            let oldest = *dq.front().expect("non-empty when at limit");
            let retry = self.window.saturating_sub(now.duration_since(oldest));
            return Err(RateLimited {
                retry_after_secs: retry.as_secs().max(1),
            });
        }

        dq.push_back(now);
        Ok(())
    }

    /// Global concurrency semaphore, acquired by each running sandbox scan.
    pub fn semaphore(&self) -> Arc<Semaphore> {
        self.sem.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_rejects() {
        let limiter = Limiter::new(3, 4);
        assert!(limiter.check_and_record("ip").is_ok());
        assert!(limiter.check_and_record("ip").is_ok());
        assert!(limiter.check_and_record("ip").is_ok());
        let rejected = limiter.check_and_record("ip");
        assert!(rejected.is_err());
        assert!(rejected.err().unwrap().retry_after_secs >= 1);
        // A different IP is unaffected.
        assert!(limiter.check_and_record("other").is_ok());
    }
}
