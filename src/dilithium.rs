// Copyright (C) SandboxAQ
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;
use alloc::vec::Vec;

use der::{Decode, Encode};
use postcard;
use serde::{Deserialize, Serialize};
use trussed::{
    api::{reply, request, Reply, Request},
    backend::Backend,
    client::mechanisms,
    key,
    platform::Platform,
    service::{Keystore, ServiceResources},
    types::{
        CoreContext, Id, KeyId, KeySerialization, Mechanism, Message, Signature,
        SignatureSerialization,
    },
    Error,
};

use pkcs8::{
    AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfo, Version,
};

use pqcrypto_dilithium::dilithium2;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

mod oids {
    pub const DILITHIUM2: &str = "1.3.6.1.4.1.2.267.7.4.4";
    pub const DILITHIUM3: &str = "1.3.6.1.4.1.2.267.7.6.5";
    pub const DILITHIUM5: &str = "1.3.6.1.4.1.2.267.7.8.7";
}

fn request_kind(mechanism: &Mechanism) -> key::Kind {
    match mechanism {
        Mechanism::Dilithium2 => Ok(key::Kind::Dilithium2),
        Mechanism::Dilithium3 => Ok(key::Kind::Dilithium3),
        Mechanism::Dilithium5 => Ok(key::Kind::Dilithium5),
        _ => Err(Error::RequestNotAvailable),
    }
    .expect("Unsupported request mechanism")
}

#[derive(Serialize, Deserialize)]
struct PrivateKeyPkcs8WithPublicKeyId<'a> {
    pub_key_id: KeyId,
    priv_key_der_bytes: &'a [u8],
}

fn store_key_dilithium(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
    oid: &str,
    pub_key_bytes: &[u8],
    priv_key_bytes: &[u8],
) -> Result<reply::GenerateKey, Error> {
    let pub_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        key::Info::from(request_kind(&request.mechanism)).with_local_flag(),
        &pub_key_bytes[..],
    )?;

    let priv_key_pkcs8 = pkcs8::PrivateKeyInfo::new(
        AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new(oid).expect("Failed to create object identifier"),
            parameters: None,
        },
        priv_key_bytes,
    );
    let priv_key_der_bytes = priv_key_pkcs8
        .to_der()
        .expect("Failed to encode Dilithium key PKCS#8 to DER");

    let wrapped_key = PrivateKeyPkcs8WithPublicKeyId {
        priv_key_der_bytes: &priv_key_der_bytes[..],
        pub_key_id: pub_key_id,
    };

    let wrapped_bytes: Vec<u8> = postcard::to_allocvec(&wrapped_key).unwrap();

    let priv_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Secret,
        key::Info::from(request_kind(&request.mechanism)).with_local_flag(),
        &wrapped_bytes[..],
    )?;

    Ok(reply::GenerateKey { key: priv_key_id })
}

fn generate_key_dilithium2(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    let (pub_key, priv_key) = dilithium2::keypair();
    store_key_dilithium(
        keystore,
        request,
        oids::DILITHIUM2,
        pub_key.as_bytes(),
        priv_key.as_bytes(),
    )
}
fn generate_key_dilithium3(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    let (pub_key, priv_key) = dilithium3::keypair();
    store_key_dilithium(
        keystore,
        request,
        oids::DILITHIUM3,
        pub_key.as_bytes(),
        priv_key.as_bytes(),
    )
}
fn generate_key_dilithium5(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    let (pub_key, priv_key) = dilithium2::keypair();
    store_key_dilithium(
        keystore,
        request,
        oids::DILITHIUM5,
        pub_key.as_bytes(),
        priv_key.as_bytes(),
    )
}

fn generate_key(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    let res = match request.mechanism {
        Mechanism::Dilithium2 => generate_key_dilithium2(keystore, request),
        Mechanism::Dilithium3 => generate_key_dilithium3(keystore, request),
        Mechanism::Dilithium5 => generate_key_dilithium5(keystore, request),
        _ => Err(Error::RequestNotAvailable),
    }
    .expect("Unknown key kind for key generation");

    Ok(res)
}

fn derive_key(
    keystore: &mut impl Keystore,
    request: &request::DeriveKey,
) -> Result<reply::DeriveKey, Error> {
    // Retrieve private key
    let base_key_id = &request.base_key;
    let priv_key_der = keystore
        .load_key(
            key::Secrecy::Secret,
            Some(request_kind(&request.mechanism)),
            base_key_id,
        )
        .expect("Failed to load a Dilithium private key with the given ID")
        .material;

    // We can't derive a public key from a private key when using Dilithium. Instead,
    // we generated the public key at the same time as the private key in generate_key,
    // and we just retrieve it here instead of deriving it anew.
    let wrapped_key: PrivateKeyPkcs8WithPublicKeyId = postcard::from_bytes(&priv_key_der).unwrap();

    Ok(reply::DeriveKey {
        key: wrapped_key.pub_key_id,
    })
}

fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
    let key_id = request.key;

    let priv_key_der = keystore
        .load_key(
            key::Secrecy::Secret,
            Some(request_kind(&request.mechanism)),
            &key_id,
        )
        .expect("Failed to load a Dilithium private key with the given ID")
        .material;

    let wrapped_key: PrivateKeyPkcs8WithPublicKeyId = postcard::from_bytes(&priv_key_der).unwrap();

    let priv_key_pkcs8 = pkcs8::PrivateKeyInfo::from_der(wrapped_key.priv_key_der_bytes)
        .expect("Failed to decode Dilithium PKCS#8 from DER");

    match request.mechanism {
        Mechanism::Dilithium2 => {
            let priv_key = dilithium2::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load Dilithium key from PKCS#8");
            let signed_message = dilithium2::sign(&request.message, &priv_key);
            return Ok(reply::Sign {
                signature: Signature::from_slice(signed_message.as_bytes())
                    .expect("Failed to build signature from signed message bytes"),
            });
        }
        Mechanism::Dilithium3 => {
            let priv_key = dilithium3::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load Dilithium key from PKCS#8");
            let signed_message = dilithium3::sign(&request.message, &priv_key);
            return Ok(reply::Sign {
                signature: Signature::from_slice(signed_message.as_bytes())
                    .expect("Failed to build signature from signed message bytes"),
            });
        }
        Mechanism::Dilithium5 => {
            let priv_key = dilithium5::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load Dilithium key from PKCS#8");
            let signed_message = dilithium5::sign(&request.message, &priv_key);
            return Ok(reply::Sign {
                signature: Signature::from_slice(signed_message.as_bytes())
                    .expect("Failed to build signature from signed message bytes"),
            });
        }
        _ => Err(Error::RequestNotAvailable),
    }
}

pub struct Dilithium;

impl Dilithium {}

impl Backend for Dilithium {
    type Context = ();
    fn request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let mut rng = resources.rng()?;
        let mut keystore = resources.keystore(core_ctx)?;
        match request {
            Request::DeriveKey(req) => derive_key(&mut keystore, req).map(Reply::DeriveKey),
            // Request::DeserializeKey(req) => {
            //     let (bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
            //     deserialize_key(&mut keystore, req, bits, kind).map(Reply::DeserializeKey)
            // }
            // Request::SerializeKey(req) => {
            //     let (_bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
            //     serialize_key(&mut keystore, req, kind).map(Reply::SerializeKey)
            // }
            Request::GenerateKey(req) => generate_key(&mut keystore, req).map(Reply::GenerateKey),
            Request::Sign(req) => sign(&mut keystore, req).map(Reply::Sign),
            // Request::Verify(req) => {
            //     let (bits, kind, raw) = bits_and_kind_from_mechanism(req.mechanism)?;
            //     if raw {
            //         warn!("Attempt at raw verify");
            //         return Err(Error::MechanismInvalid);
            //     }
            //     verify(&mut keystore, req, bits, kind).map(Reply::Verify)
            // }
            // Request::Decrypt(req) => {
            //     let (bits, kind, raw) = bits_and_kind_from_mechanism(req.mechanism)?;
            //     if raw {
            //         rsa_raw(&mut keystore, req.key, &req.message, kind, bits, &mut rng)
            //             .map(|r| Reply::Decrypt(reply::Decrypt { plaintext: Some(r) }))
            //     } else {
            //         decrypt(&mut keystore, req, kind).map(Reply::Decrypt)
            //     }
            // }
            // Request::UnsafeInjectKey(req) => {
            //     let (bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
            //     unsafe_inject_key(&mut keystore, req, bits, kind).map(Reply::UnsafeInjectKey)
            // }
            // Request::Exists(req) => {
            //     let (_bits, kind, _) = bits_and_kind_from_mechanism(req.mechanism)?;
            //     exists(&mut keystore, req, kind).map(Reply::Exists)
            // }
            //_ => Err(Error::RequestNotAvailable),
        }
    }
}
