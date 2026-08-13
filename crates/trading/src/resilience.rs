//! Resilience primitives (roadmap Phase 5): exponential backoff with jitter,
//! a retry loop, and a circuit breaker for exchange/network calls.
//!
//! ```text
//!                ┌────────────┐   failure ≥ threshold   ┌──────────┐
//!   ──▶ Closed ──▶  Closed    ──────────────────────────▶  Open    ──┐
//!   │  (counting failures)    ◀─────────────────────────  (rejects)  │
//!   │                          after timeout (half-open probe)       │
//!   └── success resets ──────┘                          ┌──────────┘
//!                                                       ▼
//! ```

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Exponential backoff with *full jitter* (AWS's "sleep with jitter"
/// strategy): `sleep = random(0, min(cap, base * 2^attempt))`. Jitter keeps
/// a fleet of retrying clients from thundering-herding into the same window.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    factor: f64,
    attempt: u32,
}

impl Backoff {
    /// `base` is the first delay; `cap` bounds the exponential growth.
    pub fn new(base: Duration, cap: Duration) -> Backoff {
        Backoff {
            base,
            cap,
            factor: 2.0,
            attempt: 0,
        }
    }

    /// The delay to sleep *before the next attempt*. Calling this bumps the
    /// attempt counter, so it must be called at most once per retry.
    pub fn next_delay(&mut self) -> Duration {
        let exp = self.base.as_millis() as f64 * self.factor.powi(self.attempt as i32);
        let capped = exp.min(self.cap.as_millis() as f64);
        self.attempt += 1;
        // full jitter: uniform in [0, capped]
        let jittered = (capped * rand_f64()).min(capped);
        Duration::from_millis(jittered.max(1.0) as u64)
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Uniform `f64` in `[0, 1)` — a tiny xorshift so the module stays
/// dependency-free (no `rand` in trading).
fn rand_f64() -> f64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0x9E37_79B9_7F4A_7C15) };
    }
    STATE.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        (x >> 11) as f64 / (1u64 << 53) as f64
    })
}

/// Retry `f` until it succeeds or `max_attempts` have been made, sleeping
/// [`Backoff`] between attempts. Use for idempotent reads (fetching klines,
/// querying a node); never for non-idempotent writes.
pub fn retry_with_backoff<T, E, F>(
    mut f: F,
    max_attempts: u32,
    backoff: &mut Backoff,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(_) if backoff.attempt() + 1 < max_attempts => {
                std::thread::sleep(backoff.next_delay());
            }
            Err(e) => return Err(e),
        }
    }
}

/// Errors from a short-circuited [`CircuitBreaker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitOpen;

/// A stateful circuit breaker.
///
/// - **Closed**: calls pass through; failures are counted.
/// - **Open**: after `failure_threshold` consecutive failures, calls are
///   rejected immediately (fast fail, no hammering a dead exchange) for
///   `timeout`. Then a single half-open probe is allowed.
/// - **HalfOpen**: one probe passes; success closes the circuit, failure
///   reopens it for another `timeout`.
#[derive(Debug)]
pub struct CircuitBreaker {
    state: Mutex<State>,
    failure_threshold: u32,
    timeout: Duration,
    /// Concurrent probes while half-open (1 = classic circuit breaker).
    half_open_max: u32,
}

#[derive(Debug, Clone)]
enum State {
    Closed { failures: u32 },
    Open { until: Instant },
    HalfOpen { in_flight: u32 },
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, timeout: Duration) -> CircuitBreaker {
        CircuitBreaker {
            state: Mutex::new(State::Closed { failures: 0 }),
            failure_threshold: failure_threshold.max(1),
            timeout,
            half_open_max: 1,
        }
    }

    /// Run `f`, observing its result against the breaker state.
    ///
    /// Returns `Err(CircuitOpen)` without calling `f` while open. The caller
    /// decides what a failure is: map transport errors to `Err(())` and treat
    /// HTTP 5xx as failures too, if desired.
    pub fn call<T, E, F>(&self, f: F) -> Result<T, CircuitBreakerResult<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let mut state = self.state.lock().unwrap();
        match *state {
            State::Open { until } if until > Instant::now() => {
                return Err(CircuitBreakerResult::Open(CircuitOpen));
            }
            State::Open { .. } => {
                // Timeout elapsed: transition to half-open with one probe.
                *state = State::HalfOpen { in_flight: 0 };
            }
            _ => {}
        }

        let _probe = match &mut *state {
            State::HalfOpen { in_flight } if *in_flight >= self.half_open_max => {
                return Err(CircuitBreakerResult::Open(CircuitOpen));
            }
            State::HalfOpen { in_flight } => {
                *in_flight += 1;
                true
            }
            _ => false,
        };

        // Never hold the state lock while executing user code. Besides
        // serializing all callers, keeping this guard alive would deadlock
        // below when we lock the state again to record the result.
        drop(state);
        let result = f();
        let mut state = self.state.lock().unwrap();
        match result {
            Ok(v) => {
                *state = State::Closed { failures: 0 };
                Ok(v)
            }
            Err(e) => {
                match &mut *state {
                    State::Closed { failures } => {
                        *failures += 1;
                        if *failures >= self.failure_threshold {
                            *state = State::Open {
                                until: Instant::now() + self.timeout,
                            };
                        }
                    }
                    State::HalfOpen { in_flight } => {
                        *in_flight -= 1;
                        *state = State::Open {
                            until: Instant::now() + self.timeout,
                        };
                    }
                    State::Open { .. } => unreachable!("we passed the open check"),
                }
                Err(CircuitBreakerResult::Failure(e))
            }
        }
    }

    /// Snapshot of the breaker's health, for metrics.
    pub fn state(&self) -> BreakerState {
        let s = self.state.lock().unwrap();
        match *s {
            State::Closed { failures } => BreakerState::Closed { failures },
            State::Open { .. } => BreakerState::Open,
            State::HalfOpen { .. } => BreakerState::HalfOpen,
        }
    }
}

/// A "did we even call the backend" wrapper for [`CircuitBreaker::call`].
#[derive(Debug)]
pub enum CircuitBreakerResult<T> {
    /// The breaker rejected the call without hitting the backend.
    Open(CircuitOpen),
    /// The backend was called and failed.
    Failure(T),
}

impl<T> CircuitBreakerResult<T> {
    pub fn into_failure(self) -> Option<T> {
        match self {
            CircuitBreakerResult::Open(_) => None,
            CircuitBreakerResult::Failure(e) => Some(e),
        }
    }
}

/// Snapshot of breaker health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed { failures: u32 },
    Open,
    HalfOpen,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(1));
        let mut seen = Vec::new();
        for _ in 0..10 {
            let d = b.next_delay();
            assert!(d >= Duration::from_millis(1));
            assert!(d <= Duration::from_secs(1), "capped at 1s, got {d:?}");
            seen.push(d);
        }
        // Later delays are statistically larger (exponential base * 2^n).
        let early: u64 = seen[..3].iter().map(|d| d.as_millis() as u64).sum();
        let late: u64 = seen[7..].iter().map(|d| d.as_millis() as u64).sum();
        assert!(late > early, "backoff must grow: early {early} late {late}");
    }

    #[test]
    fn retry_succeeds_after_transient_failures() {
        let mut calls = 0;
        let mut backoff = Backoff::new(Duration::from_millis(1), Duration::from_millis(5));
        let out = retry_with_backoff(
            || {
                calls += 1;
                if calls < 3 {
                    Err("transient")
                } else {
                    Ok(42)
                }
            },
            5,
            &mut backoff,
        );
        assert_eq!(out, Ok(42));
        assert_eq!(calls, 3);
    }

    #[test]
    fn retry_gives_up_after_max_attempts() {
        let mut calls = 0;
        let mut backoff = Backoff::new(Duration::from_millis(1), Duration::from_millis(5));
        let out: Result<i32, &str> = retry_with_backoff(
            || {
                calls += 1;
                Err("always fails")
            },
            3,
            &mut backoff,
        );
        assert!(out.is_err());
        assert_eq!(calls, 3);
    }

    #[test]
    fn breaker_opens_after_threshold_then_half_open_probes() {
        let b = CircuitBreaker::new(3, Duration::from_millis(20));
        // 2 failures: still closed.
        for _ in 0..2 {
            let r: CircuitBreakerResult<i32> =
                b.call(|| -> Result<i32, i32> { Err(1) }).unwrap_err();
            assert!(r.into_failure().is_some());
        }
        assert_eq!(b.state(), BreakerState::Closed { failures: 2 });
        // 3rd failure: opens.
        let r: CircuitBreakerResult<i32> = b.call(|| -> Result<i32, i32> { Err(1) }).unwrap_err();
        assert!(matches!(r, CircuitBreakerResult::Failure(1)));
        assert_eq!(b.state(), BreakerState::Open);
        // While open, calls are rejected without invoking the closure.
        let mut invoked = false;
        let r: CircuitBreakerResult<i32> = b
            .call(|| {
                invoked = true;
                Ok(0)
            })
            .unwrap_err();
        assert!(matches!(r, CircuitBreakerResult::Open(_)));
        assert!(!invoked);
        // After the timeout, one probe passes; success closes the breaker.
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(b.call(|| -> Result<i32, i32> { Ok(7) }).unwrap(), 7); // Ok path
        assert_eq!(b.state(), BreakerState::Closed { failures: 0 });
    }

    #[test]
    fn breaker_reopens_on_half_open_failure() {
        let b = CircuitBreaker::new(2, Duration::from_millis(20));
        let _: CircuitBreakerResult<i32> = b.call(|| -> Result<i32, i32> { Err(1) }).unwrap_err();
        let _: CircuitBreakerResult<i32> = b.call(|| -> Result<i32, i32> { Err(1) }).unwrap_err();
        assert_eq!(b.state(), BreakerState::Open);
        std::thread::sleep(Duration::from_millis(30));
        // Probe fails => reopens.
        let r: CircuitBreakerResult<i32> = b.call(|| -> Result<i32, i32> { Err(9) }).unwrap_err();
        assert!(r.into_failure().is_some());
        assert_eq!(b.state(), BreakerState::Open);
    }
}
