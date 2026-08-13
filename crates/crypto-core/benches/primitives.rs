//! Microbenchmarks for the Phase 1 primitives (roadmap Phase 0 checklist:
//! "Benchmarks harness (criterion) wired in").
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p crypto-core
//! ```
//!
//! Each group measures a hot path a wallet/node would actually run:
//! hashing, HMAC, AEAD, key derivation, and ECDSA sign/verify.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

use crypto_core::aead;
use crypto_core::hash::{hash256, hmac_sha256, keccak256, sha256};
use crypto_core::kdf::{hkdf_sha256, pbkdf2_sha256};
use crypto_core::sign::{keypair_from_seed, sign_digest, verify_digest};

const DATA: &[u8] = b"the quick brown fox jumps over the lazy dog 0123456789";
const KEY: [u8; 32] = [7u8; 32];

fn bench_hashes(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash");
    g.throughput(criterion::Throughput::Bytes(DATA.len() as u64));
    g.bench_function("sha256", |b| b.iter(|| sha256(DATA)));
    g.bench_function("hash256 (double-sha256)", |b| b.iter(|| hash256(DATA)));
    g.bench_function("keccak256", |b| b.iter(|| keccak256(DATA)));
    g.bench_function("hmac-sha256", |b| b.iter(|| hmac_sha256(&KEY, DATA)));
    g.finish();
}

fn bench_aead(c: &mut Criterion) {
    let mut g = c.benchmark_group("aead");
    let nonce = [3u8; 12];
    g.bench_function("aes-256-gcm seal+open", |b| {
        b.iter_batched(
            || aead::encrypt_aes_gcm_with_nonce(&KEY, nonce, DATA, &[]).unwrap(),
            |ct| aead::decrypt_aes_gcm(&KEY, &ct, &[]).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("chacha20-poly1305 seal+open", |b| {
        b.iter_batched(
            || aead::encrypt_chacha_with_nonce(&KEY, nonce, DATA, &[]).unwrap(),
            |ct| aead::decrypt_chacha(&KEY, &ct, &[]).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_kdf(c: &mut Criterion) {
    let mut g = c.benchmark_group("kdf");
    g.bench_function("hkdf-sha256 (48 bytes)", |b| {
        b.iter(|| hkdf_sha256(&KEY, b"", DATA, 48))
    });
    // PBKDF2 is deliberately expensive: keystore decryption with the default
    // 262144 iterations takes ~50-100ms; bench with the production count so
    // regressions in the hot loop show up as wall time.
    g.bench_function("pbkdf2-sha256 (262144 iters)", |b| {
        b.iter(|| pbkdf2_sha256(b"correct horse battery staple", &KEY, 262_144, 32))
    });
    g.finish();
}

fn bench_ecdsa(c: &mut Criterion) {
    let (sk, pk) = keypair_from_seed(&[9u8; 32]);
    let digest = [0xab; 32];
    let sig = sign_digest(&sk, &digest);
    let mut g = c.benchmark_group("ecdsa-secp256k1");
    g.bench_function("sign (RFC 6979)", |b| b.iter(|| sign_digest(&sk, &digest)));
    g.bench_function("verify", |b| b.iter(|| verify_digest(&pk, &digest, &sig)));
    g.finish();
}

criterion_group!(benches, bench_hashes, bench_aead, bench_kdf, bench_ecdsa);
criterion_main!(benches);
