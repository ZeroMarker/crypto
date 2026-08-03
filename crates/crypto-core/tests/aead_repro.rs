use crypto_core::aead::{decrypt_aes_gcm, decrypt_chacha, encrypt_aes_gcm, encrypt_chacha};

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
