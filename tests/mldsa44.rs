// Copyright (C) SandboxAQ
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg(feature = "virt")]

use trussed::backend::Backend;
use trussed_pqc_backend::SoftwareMldsa;

use trussed::{
    client::CryptoClient,
    syscall,
    types::{
        KeyId, KeySerialization, Location::*, Mechanism, SignatureSerialization, StorageAttributes,
    },
};

use hex_literal::hex;
use trussed_pqc_backend::virt;

// Tests below can be run on a PC using the "virt" feature

#[test_log::test]
fn mldsa44_generate_key() {
    virt::with_ram_client("mldsa44 test", |mut client| {
        let sk = syscall!(client.generate_key(
            Mechanism::Mldsa44,
            StorageAttributes::new().set_persistence(Internal),
        ))
        .key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(sk, KeyId::from_special(0));
    })
}

#[test_log::test]
fn mldsa44_derive_key() {
    virt::with_ram_client("mldsa44 test", |mut client| {
        let sk = syscall!(client.generate_key(
            Mechanism::Mldsa44,
            StorageAttributes::new().set_persistence(Internal)
        ))
        .key;
        let pk = syscall!(client.derive_key(
            Mechanism::Mldsa44,
            sk,
            None,
            StorageAttributes::new().set_persistence(Volatile)
        ))
        .key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(pk, KeyId::from_special(0));
    })
}

#[test_log::test]
fn mldsa44_exists_key() {
    virt::with_ram_client("mldsa44 test", |mut client| {
        let sk = syscall!(client.generate_key(
            Mechanism::Mldsa44,
            StorageAttributes::new().set_persistence(Internal)
        ))
        .key;
        let key_exists = syscall!(client.exists(Mechanism::Mldsa44, sk)).exists;

        assert!(key_exists);
    })
}

#[test_log::test]
fn mldsa44_serialize_key() {
    virt::with_ram_client("mldsa44 test", |mut client| {
        let sk = syscall!(client.generate_key(
            Mechanism::Mldsa44,
            StorageAttributes::new().set_persistence(Internal)
        ))
        .key;
        let pk = syscall!(client.derive_key(
            Mechanism::Mldsa44,
            sk,
            None,
            StorageAttributes::new().set_persistence(Volatile)
        ))
        .key;

        let serialized_key =
            syscall!(client.serialize_key(Mechanism::Mldsa44, pk, KeySerialization::Pkcs8Der))
                .serialized_key;

        assert!(!serialized_key.is_empty());
    })
}

#[test_log::test]
fn mldsa44_deserialize_key() {
    virt::with_ram_client("mldsa44 test", |mut client| {
        let sk = syscall!(client.generate_key(
            Mechanism::Mldsa44,
            StorageAttributes::new().set_persistence(Internal)
        ))
        .key;
        let pk = syscall!(client.derive_key(
            Mechanism::Mldsa44,
            sk,
            None,
            StorageAttributes::new().set_persistence(Volatile)
        ))
        .key;

        let serialized_key =
            syscall!(client.serialize_key(Mechanism::Mldsa44, pk, KeySerialization::Pkcs8Der))
                .serialized_key;

        let deserialized_key_id = syscall!(client.deserialize_key(
            Mechanism::Mldsa44,
            &serialized_key,
            KeySerialization::Pkcs8Der,
            StorageAttributes::new().set_persistence(Volatile)
        ))
        .key;

        // This assumes we don't ever get a key with ID 0
        assert_ne!(deserialized_key_id, KeyId::from_special(0));
    })
}

#[test_log::test]
fn mldsa44_sign_verify() {
    virt::with_ram_client("mldsa44 test", |mut client| {
        let sk = syscall!(client.generate_key(
            Mechanism::Mldsa44,
            StorageAttributes::new().set_persistence(Internal)
        ))
        .key;
        let pk = syscall!(client.derive_key(
            Mechanism::Mldsa44,
            sk,
            None,
            StorageAttributes::new().set_persistence(Volatile)
        ))
        .key;

        let message = [1u8, 2u8, 3u8];
        let mut signature = syscall!(client.sign(
            Mechanism::Mldsa44,
            sk,
            &message,
            SignatureSerialization::Raw
        ))
        .signature;
        assert_eq!(
            signature.len(),
            pqcrypto_mldsa::ffi::PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES
        );

        // Verify that with the proper message and signature, the verification succeeds
        let verify_ok = syscall!(client.verify(
            Mechanism::Mldsa44,
            pk,
            &message,
            &signature,
            SignatureSerialization::Raw
        ))
        .valid;
        assert!(verify_ok);

        // Verify that if the message changes, the verification fails
        let wrong_message = [1u8, 2u8, 4u8];
        let verify_ok = syscall!(client.verify(
            Mechanism::Mldsa44,
            pk,
            &wrong_message,
            &signature,
            SignatureSerialization::Raw
        ))
        .valid;
        assert!(!verify_ok);

        // Verify that if the signature changes, the verification fails
        signature[0] += 1;
        let verify_ok = syscall!(client.verify(
            Mechanism::Mldsa44,
            pk,
            &message,
            &signature,
            SignatureSerialization::Raw
        ))
        .valid;
        assert!(!verify_ok);
    })
}
