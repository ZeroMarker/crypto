# Phase 5 — Production hardening

Not yet implemented. Makes the software safe enough to handle real keys or real
money.

## Checklist

1. **Secret handling**
   - Keys in a keystore encrypted with AEAD (Phase 1), not in config files.
   - Never log secrets: `tracing` targets for secret-bearing spans should be
     off by default.
   - Env/secrets manager for API keys (`secrets`, `figment`).

2. **Dependency & code audit**
   ```sh
   cargo audit          # known-vulnerability scan on the lockfile
   cargo deny check     # license + advisory policy
   cargo-fuzz fuzz_target # fuzz all parsers (RLP, headers, orders)
   ```
   Property tests with `proptest` on serializers/deserializers.

3. **Observability**
   - Structured logs via `tracing`, metrics (counters/gauges) exported to
     Prometheus, alerting on anomalies.

4. **Resilience**
   - Reconnect with backoff for WS feeds; circuit breakers around exchanges.
   - Graceful shutdown on `SIGTERM`; flush state before exiting.

5. **Failure drills**
   - `kill -9` mid-write: no state corruption.
   - Network partition: reconnection + replay protection (nonce/sequence).
   - Clock skew: reject timestamps outside a tolerance window.
   - Double-submission: idempotent order/broadcast keys.

## Done-when

A fault-injected test run completes with no funds or state corruption, and
`cargo audit` reports no known vulnerabilities.
