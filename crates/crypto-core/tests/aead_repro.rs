use crypto_core::aead::{
    decrypt_aes_gcm, decrypt_chacha, encrypt_aes_gcm, encrypt_aes_gcm_with_nonce, encrypt_chacha,
    encrypt_chacha_with_nonce,
};

#[test]
fn aes_gcm_roundtrip_with_aad() {
    let key = [7u8; 32];
    let ct = encrypt_aes_gcm(&key, b"private data", b"address-0x1234").unwrap();
    let pt = decrypt_aes_gcm(&key, &ct, b"address-0x1234").unwrap();
    assert_eq!(pt, b"private data");
}

#[test]
fn aes_gcm_wrong_aad_fails() {
    let key = [7u8; 32];
    let ct = encrypt_aes_gcm(&key, b"private data", b"address-0x1234").unwrap();
    assert!(decrypt_aes_gcm(&key, &ct, b"other-aad").is_err());
    assert!(decrypt_aes_gcm(&[8u8; 32], &ct, b"address-0x1234").is_err());
}

#[test]
fn chacha_roundtrip_with_aad() {
    let key = [9u8; 32];
    let ct = encrypt_chacha(&key, b"hello chacha", b"ctx-1").unwrap();
    let pt = decrypt_chacha(&key, &ct, b"ctx-1").unwrap();
    assert_eq!(pt, b"hello chacha");
    assert!(decrypt_chacha(&key, &ct, b"ctx-2").is_err());
}

#[test]
fn aes_gcm_nist_cavp_vector() {
    // NIST CAVP AES-256-GCM vector (from the aes-gcm crate's own test suite):
    // key / nonce / plaintext / aad chosen, expected ciphertext+tag checked.
    let key: [u8; 32] =
        hex::decode("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b")
            .unwrap()
            .try_into()
            .unwrap();
    let nonce: [u8; 12] = hex::decode("ac93a1a6145299bde902f21a")
        .unwrap()
        .try_into()
        .unwrap();
    let pt = hex::decode("2d71bcfa914e4ac045b2aa60955fad24").unwrap();
    let aad = hex::decode("1e0889016f67601c8ebea4943bc23ad6").unwrap();
    // aes-gcm's allocating encrypt() returns ciphertext || tag.
    let expected =
        hex::decode("8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab").unwrap();

    let ct = encrypt_aes_gcm_with_nonce(&key, nonce, &pt, &aad).unwrap();
    assert_eq!(ct.nonce, nonce.to_vec());
    assert_eq!(
        ct.data, expected,
        "ciphertext+tag must match the NIST vector"
    );
    assert_eq!(decrypt_aes_gcm(&key, &ct, &aad).unwrap(), pt);
}

#[test]
fn chacha20poly1305_rfc8439_vector() {
    // RFC 8439 §2.8.2 AEAD test vector (the chacha20poly1305 crate's own test).
    let key: [u8; 32] =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap()
            .try_into()
            .unwrap();
    let nonce: [u8; 12] = hex::decode("070000004041424344454647")
        .unwrap()
        .try_into()
        .unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let pt = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex::decode(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060\
         0691",
    )
    .unwrap();

    let ct = encrypt_chacha_with_nonce(&key, nonce, pt, &aad).unwrap();
    assert_eq!(ct.data, expected, "ciphertext+tag must match RFC 8439");
    assert_eq!(decrypt_chacha(&key, &ct, &aad).unwrap(), pt);
}

#[test]
fn random_nonces_never_collide_for_same_plaintext() {
    // The whole point of the random-nonce API: same plaintext, same key,
    // two encryptions must produce unrelated ciphertexts.
    let key = [42u8; 32];
    let a = encrypt_aes_gcm(&key, b"same data", b"aad").unwrap();
    let b = encrypt_aes_gcm(&key, b"same data", b"aad").unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.data, b.data);
}
