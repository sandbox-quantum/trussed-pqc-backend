// Copyright (C) SandboxAQ
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;

use der::{Decode, Encode};
use postcard;
use serde::{Deserialize, Serialize};
use trussed::{
    api::{reply, request, Reply, Request},
    backend::Backend,
    key,
    platform::Platform,
    service::{Keystore, ServiceResources},
    types::{CoreContext, KeySerialization, Mechanism, Signature, SignatureSerialization},
    Error,
};

use der::asn1::BitStringRef;
use pkcs8::AlgorithmIdentifierRef;

use pqcrypto::prelude::*;
use pqcrypto::sign::dilithium2;
use pqcrypto::sign::dilithium3;
use pqcrypto::sign::dilithium5;

mod oids {
    pub const DILITHIUM2: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.4.4");
    pub const DILITHIUM3: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.6.5");
    pub const DILITHIUM5: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.8.7");
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

fn store_key_dilithium(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
    oid: pkcs8::ObjectIdentifier,
    pub_key_bytes: &[u8],
    priv_key_bytes: &[u8],
) -> Result<reply::GenerateKey, Error> {
    let priv_key_pkcs8 = pkcs8::PrivateKeyInfo {
        algorithm: AlgorithmIdentifierRef {
            oid: oid,
            parameters: None,
        },
        private_key: priv_key_bytes,
        public_key: Some(pub_key_bytes),
    };

    let priv_key_der_bytes = priv_key_pkcs8
        .to_der()
        .expect("Failed to encode Dilithium private key PKCS#8 to DER");

    let priv_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Secret,
        key::Info::from(request_kind(&request.mechanism)).with_local_flag(),
        &priv_key_der_bytes[..],
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
    let priv_key_der_bytes = keystore
        .load_key(
            key::Secrecy::Secret,
            Some(request_kind(&request.mechanism)),
            base_key_id,
        )
        .expect("Failed to load a Dilithium private key with the given ID")
        .material;

    let priv_key_pkcs8 = pkcs8::PrivateKeyInfo::from_der(&priv_key_der_bytes[..])
        .expect("Failed to decode DER for Dilithium private key");

    let pub_key_pkcs8 = pkcs8::SubjectPublicKeyInfoRef {
        algorithm: priv_key_pkcs8.algorithm,
        subject_public_key: BitStringRef::from_bytes(priv_key_pkcs8.public_key.unwrap())
            .map_err(|_| Error::InvalidSerializedKey)?,
    };
    let pub_key_der_bytes = pub_key_pkcs8
        .to_der()
        .expect("Failed to encode Dilithium public key PKCS#8 to DER");

    let pub_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        request_kind(&request.mechanism),
        &pub_key_der_bytes[..],
    )?;

    Ok(reply::DeriveKey { key: pub_key_id })
}

fn serialize_key(
    keystore: &mut impl Keystore,
    request: &request::SerializeKey,
) -> Result<reply::SerializeKey, Error> {
    let key_id = request.key;

    // We rely on the fact that we store the keys in the PKCS#8 DER format already,
    // So these bytes are in PKCS#8 DER-encoded format
    let pub_key_der = keystore
        .load_key(
            key::Secrecy::Public,
            Some(request_kind(&request.mechanism)),
            &key_id,
        )
        .unwrap_or_else(|_| panic!("Failed to load a Dilithium public key with the given ID"))
        .material;

    let serialized_key = match request.format {
        KeySerialization::Pkcs8Der => pub_key_der.into(),
        _ => {
            return Err(Error::InvalidSerializationFormat);
        }
    };
    Ok(reply::SerializeKey { serialized_key })
}

fn deserialize_pkcs_key(
    keystore: &mut impl Keystore,
    request: &request::DeserializeKey,
) -> Result<reply::DeserializeKey, Error> {
    let pub_key = pkcs8::SubjectPublicKeyInfoRef::from_der(&request.serialized_key)
        .map_err(|_| Error::InvalidSerializationFormat)?;

    // TODO: check key lengths for each of these
    match pub_key.algorithm.oid {
        oids::DILITHIUM2 => {}
        oids::DILITHIUM3 => {}
        oids::DILITHIUM5 => {}
        _ => return Err(Error::InvalidSerializationFormat),
    }

    // We store our keys in PKCS#8 DER format
    let pub_key_der = pub_key
        .to_der()
        .unwrap_or_else(|_| panic!("Failed to serialize a Dilithium public key to PKCS#8 DER"));

    let pub_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        request_kind(&request.mechanism),
        pub_key_der.as_ref(),
    )?;

    Ok(reply::DeserializeKey { key: pub_key_id })
}

fn deserialize_key(
    keystore: &mut impl Keystore,
    request: &request::DeserializeKey,
) -> Result<reply::DeserializeKey, Error> {
    match request.format {
        KeySerialization::Pkcs8Der => deserialize_pkcs_key(keystore, request),
        _ => Err(Error::InvalidSerializationFormat),
    }
}

fn exists(keystore: &mut impl Keystore, request: &request::Exists) -> Result<reply::Exists, Error> {
    let key_id = request.key;

    let exists = keystore.exists_key(
        key::Secrecy::Secret,
        Some(request_kind(&request.mechanism)),
        &key_id,
    );
    Ok(reply::Exists { exists })
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

    let priv_key_pkcs8 = pkcs8::PrivateKeyInfo::from_der(&priv_key_der[..])
        .expect("Failed to decode Dilithium PKCS#8 from DER");

    // TODO: check if this is returning just the signature, or the signed message
    match request.mechanism {
        Mechanism::Dilithium2 => {
            let priv_key = dilithium2::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load Dilithium key from PKCS#8");
            let signed_message = dilithium2::detached_sign(&request.message, &priv_key);
            return Ok(reply::Sign {
                signature: Signature::from_slice(signed_message.as_bytes())
                    .expect("Failed to build signature from signed message bytes"),
            });
        }
        Mechanism::Dilithium3 => {
            let priv_key = dilithium3::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load Dilithium key from PKCS#8");
            let signed_message = dilithium3::detached_sign(&request.message, &priv_key);
            return Ok(reply::Sign {
                signature: Signature::from_slice(signed_message.as_bytes())
                    .expect("Failed to build signature from signed message bytes"),
            });
        }
        Mechanism::Dilithium5 => {
            let priv_key = dilithium5::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load Dilithium key from PKCS#8");
            let signed_message = dilithium5::detached_sign(&request.message, &priv_key);
            return Ok(reply::Sign {
                signature: Signature::from_slice(signed_message.as_bytes())
                    .expect("Failed to build signature from signed message bytes"),
            });
        }
        _ => Err(Error::RequestNotAvailable),
    }
}

fn verify(keystore: &mut impl Keystore, request: &request::Verify) -> Result<reply::Verify, Error> {
    if let SignatureSerialization::Raw = request.format {
    } else {
        return Err(Error::InvalidSerializationFormat);
    }

    let key_id = request.key;

    let pub_key_der = keystore
        .load_key(
            key::Secrecy::Public,
            Some(request_kind(&request.mechanism)),
            &key_id,
        )
        .unwrap_or_else(|_| panic!("Failed to load a Dilithium public key with the given ID"))
        .material;

    let pub_key_pkcs8 = pkcs8::SubjectPublicKeyInfoRef::from_der(&pub_key_der[..])
        .expect("Failed to decode Dilithium PKCS#8 from DER");

    let pub_key_bytes = match pub_key_pkcs8.subject_public_key.as_bytes() {
        Some(b) => b,
        None => return Err(Error::InvalidSerializationFormat),
    };

    match request.mechanism {
        Mechanism::Dilithium2 => {
            let pub_key = dilithium2::PublicKey::from_bytes(pub_key_bytes)
                .expect("Failed to load Dilithium public key");
            let sig = match dilithium2::DetachedSignature::from_bytes(request.signature.as_slice())
            {
                Ok(sig) => sig,
                Err(_) => return Err(Error::WrongSignatureLength),
            };
            let verification_ok =
                dilithium2::verify_detached_signature(&sig, &request.message, &pub_key).is_ok();
            Ok(reply::Verify {
                valid: verification_ok,
            })
        }
        Mechanism::Dilithium3 => {
            let pub_key = dilithium3::PublicKey::from_bytes(pub_key_bytes)
                .expect("Failed to load Dilithium public key");
            let sig = match dilithium3::DetachedSignature::from_bytes(request.signature.as_slice())
            {
                Ok(sig) => sig,
                Err(_) => return Err(Error::WrongSignatureLength),
            };
            let verification_ok =
                dilithium3::verify_detached_signature(&sig, &request.message, &pub_key).is_ok();
            Ok(reply::Verify {
                valid: verification_ok,
            })
        }
        Mechanism::Dilithium5 => {
            let pub_key = dilithium5::PublicKey::from_bytes(pub_key_bytes)
                .expect("Failed to load Dilithium public key");
            let sig = match dilithium5::DetachedSignature::from_bytes(request.signature.as_slice())
            {
                Ok(sig) => sig,
                Err(_) => return Err(Error::WrongSignatureLength),
            };
            let verification_ok =
                dilithium5::verify_detached_signature(&sig, &request.message, &pub_key).is_ok();
            Ok(reply::Verify {
                valid: verification_ok,
            })
        }
        _ => Err(Error::RequestNotAvailable),
    }
}
pub struct Dilithium;

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
        let mut keystore = resources.keystore(core_ctx.path.clone())?;
        match request {
            Request::DeriveKey(req) => derive_key(&mut keystore, req).map(Reply::DeriveKey),
            Request::DeserializeKey(req) => {
                deserialize_key(&mut keystore, req).map(Reply::DeserializeKey)
            }
            Request::SerializeKey(req) => {
                serialize_key(&mut keystore, req).map(Reply::SerializeKey)
            }
            Request::GenerateKey(req) => generate_key(&mut keystore, req).map(Reply::GenerateKey),
            Request::Sign(req) => sign(&mut keystore, req).map(Reply::Sign),
            Request::Verify(req) => verify(&mut keystore, req).map(Reply::Verify),
            Request::Exists(req) => exists(&mut keystore, req).map(Reply::Exists),
            _ => Err(Error::RequestNotAvailable),
        }
    }
}
