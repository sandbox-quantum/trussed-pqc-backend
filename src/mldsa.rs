// Copyright (C) SandboxAQ
// SPDX-License-Identifier: Apache-2.0 or MIT

extern crate alloc;

use cosey;
use der::asn1::BitStringRef;
use der::{Decode, Encode};
use pkcs8::AlgorithmIdentifierRef;
use pqcrypto_traits::sign::DetachedSignature;
use pqcrypto_traits::sign::PublicKey;
use pqcrypto_traits::sign::SecretKey;
use trussed::{
    api::{reply, request, Reply, Request},
    backend::Backend,
    key,
    platform::Platform,
    service::{Keystore, ServiceResources},
    types::{
        Bytes, CoreContext, KeySerialization, Mechanism, SerializedKey, Signature,
        SignatureSerialization,
    },
    Error,
};
use trussed_core::config::MAX_SERIALIZED_KEY_LENGTH;

#[cfg(feature = "mldsa44")]
use pqcrypto_mldsa::mldsa44;
#[cfg(feature = "mldsa65")]
use pqcrypto_mldsa::mldsa65;
#[cfg(feature = "mldsa87")]
use pqcrypto_mldsa::mldsa87;

// TODO: These are the old Dilithium 2/3/5 OIDs.
// They should be replaced with the ML-DSA OIDs.
mod oids {
    #[cfg(feature = "mldsa44")]
    pub const MLDSA44: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.4.4");
    #[cfg(feature = "mldsa65")]
    pub const MLDSA65: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.6.5");
    #[cfg(feature = "mldsa87")]
    pub const MLDSA87: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.8.7");
}

fn request_kind(mechanism: &Mechanism) -> Result<key::Kind, Error> {
    match mechanism {
        #[cfg(feature = "mldsa44")]
        Mechanism::Mldsa44 => Ok(key::Kind::Mldsa44),
        #[cfg(feature = "mldsa65")]
        Mechanism::Mldsa65 => Ok(key::Kind::Mldsa65),
        #[cfg(feature = "mldsa87")]
        Mechanism::Mldsa87 => Ok(key::Kind::Mldsa87),
        _ => Err(Error::RequestNotAvailable),
    }
}

fn store_key_mldsa(
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
        .expect("Failed to encode ML-DSA private key PKCS#8 to DER");

    let priv_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Secret,
        key::Info::from(request_kind(&request.mechanism)?).with_local_flag(),
        &priv_key_der_bytes[..],
    )?;

    Ok(reply::GenerateKey { key: priv_key_id })
}

#[cfg(feature = "mldsa44")]
fn generate_key_mldsa_44(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    let (pub_key, priv_key) = mldsa44::keypair();
    store_key_mldsa(
        keystore,
        request,
        oids::MLDSA44,
        pub_key.as_bytes(),
        priv_key.as_bytes(),
    )
}
#[cfg(feature = "mldsa65")]
fn generate_key_mldsa_65(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    let (pub_key, priv_key) = mldsa65::keypair();
    store_key_mldsa(
        keystore,
        request,
        oids::MLDSA65,
        pub_key.as_bytes(),
        priv_key.as_bytes(),
    )
}
#[cfg(feature = "mldsa87")]
fn generate_key_mldsa_87(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    let (pub_key, priv_key) = mldsa87::keypair();
    store_key_mldsa(
        keystore,
        request,
        oids::MLDSA87,
        pub_key.as_bytes(),
        priv_key.as_bytes(),
    )
}

fn generate_key(
    keystore: &mut impl Keystore,
    request: &request::GenerateKey,
) -> Result<reply::GenerateKey, Error> {
    match request.mechanism {
        #[cfg(feature = "mldsa44")]
        Mechanism::Mldsa44 => generate_key_mldsa_44(keystore, request),
        #[cfg(feature = "mldsa65")]
        Mechanism::Mldsa65 => generate_key_mldsa_65(keystore, request),
        #[cfg(feature = "mldsa87")]
        Mechanism::Mldsa87 => generate_key_mldsa_87(keystore, request),
        _ => Err(Error::RequestNotAvailable),
    }
}

fn derive_key(
    keystore: &mut impl Keystore,
    request: &request::DeriveKey,
) -> Result<reply::DeriveKey, Error> {
    // Retrieve private key
    let base_key_id = &request.base_key;
    // TODO: figure out why, with the max material length set appropriately, it chops off 4 bytes
    let priv_key_der_bytes = keystore
        .load_key(
            key::Secrecy::Secret,
            Some(request_kind(&request.mechanism)?),
            base_key_id,
        )
        .expect("Failed to load a ML-DSA private key with the given ID")
        .material;

    let priv_key_pkcs8 = pkcs8::PrivateKeyInfo::from_der(&priv_key_der_bytes[..])
        .expect("Failed to decode DER for ML-DSA private key");

    let pub_key_pkcs8 = pkcs8::SubjectPublicKeyInfoRef {
        algorithm: priv_key_pkcs8.algorithm,
        subject_public_key: BitStringRef::from_bytes(priv_key_pkcs8.public_key.unwrap())
            .map_err(|_| Error::InvalidSerializedKey)?,
    };
    let pub_key_der_bytes = pub_key_pkcs8
        .to_der()
        .expect("Failed to encode ML-DSA public key PKCS#8 to DER");

    let pub_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        request_kind(&request.mechanism)?,
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
            Some(request_kind(&request.mechanism)?),
            &key_id,
        )
        .unwrap_or_else(|_| panic!("Failed to load a ML-DSA public key with the given ID"))
        .material;

    let serialized_key: Bytes<MAX_SERIALIZED_KEY_LENGTH> = match request.format {
        KeySerialization::Cose => {
            let pub_key_der = pkcs8::SubjectPublicKeyInfoRef::from_der(&pub_key_der)
                .map_err(|_| Error::InvalidSerializationFormat)?;
            let pub_key_bytes = pub_key_der.subject_public_key.raw_bytes();
            match pub_key_der.algorithm.oid {
                #[cfg(feature = "mldsa44")]
                oids::MLDSA44 => {
                    let cose_pk = cosey::Mldsa44PublicKey {
                        pk: Bytes::from_slice(pub_key_bytes).unwrap(),
                    };
                    trussed::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
                }
                #[cfg(feature = "mldsa65")]
                oids::MLDSA65 => {
                    let cose_pk = cosey::Mldsa65PublicKey {
                        pk: Bytes::from_slice(pub_key_bytes).unwrap(),
                    };
                    trussed::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
                }
                #[cfg(feature = "mldsa87")]
                oids::MLDSA87 => {
                    let cose_pk = cosey::Mldsa87PublicKey {
                        pk: Bytes::from_slice(pub_key_bytes).unwrap(),
                    };
                    trussed::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
                }
                _ => return Err(Error::WrongKeyKind),
            }
        }

        KeySerialization::Raw => {
            let mut data = SerializedKey::new();
            data.extend_from_slice(&pub_key_der[..])
                .map_err(|_| Error::InternalError)?;
            data
        }
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
        #[cfg(feature = "mldsa44")]
        oids::MLDSA44 => {}
        #[cfg(feature = "mldsa65")]
        oids::MLDSA65 => {}
        #[cfg(feature = "mldsa87")]
        oids::MLDSA87 => {}
        _ => return Err(Error::InvalidSerializationFormat),
    }

    // We store our keys in PKCS#8 DER format
    let pub_key_der = pub_key
        .to_der()
        .unwrap_or_else(|_| panic!("Failed to serialize a ML-DSA public key to PKCS#8 DER"));

    let pub_key_id = keystore.store_key(
        request.attributes.persistence,
        key::Secrecy::Public,
        request_kind(&request.mechanism)?,
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
        // TODO: complete
        // KeySerialization::Cose => {
        //     let pk: Result<Bytes, Error> = match request.mechanism {
        //         Mechanism::Mldsa44 => {
        //             let cose_public_key: cosey::Mldsa44PublicKey = cbor_deserialize(&request.serialized_key).map_err(|_| Error::CborError);
        //             cose_public_key.into()
        //         }
        //         Mechanism::Mldsa65 => {
        //             let cose_public_key: cosey::Mldsa65PublicKey = cbor_deserialize(&request.serialized_key).map_err(|_| Error::CborError);
        //             cose_public_key.into()
        //         }
        //         Mechanism::Mldsa87 => {
        //             let cose_public_key: cosey::Mldsa87PublicKey = cbor_deserialize(&request.serialized_key).map_err(|_| Error::CborError);
        //             cose_public_key.into()
        //         }
        //         _ => Err(Error::RequestNotAvailable),
        //     };

        //     // TODO: this should all be done upstream
        //     let cose_public_key: cosey::P256PublicKey =
        //         crate::cbor_deserialize(&request.serialized_key)
        //             .map_err(|_| Error::CborError)?;
        //     let mut serialized_key = [0u8; 64];
        //     if cose_public_key.x.len() != 32 || cose_public_key.y.len() != 32 {
        //         return Err(Error::InvalidSerializedKey);
        //     }

        //     serialized_key[..32].copy_from_slice(&cose_public_key.x);
        //     serialized_key[32..].copy_from_slice(&cose_public_key.y);

        //     p256_cortex_m4::PublicKey::from_untagged_bytes(&serialized_key)
        //         .map_err(|_| Error::InvalidSerializedKey)?
        // }

        // KeySerialization::Raw => {
        //     let mut serialized_key = [0u8; 64];
        //     serialized_key.copy_from_slice(&request.serialized_key[..64]);

        //     p256_cortex_m4::PublicKey::from_untagged_bytes(&serialized_key)
        //         .map_err(|_| Error::InvalidSerializedKey)?
        // }
        _ => Err(Error::InvalidSerializationFormat),
    }
}

fn exists(keystore: &mut impl Keystore, request: &request::Exists) -> Result<reply::Exists, Error> {
    let key_id = request.key;

    let exists = keystore.exists_key(
        key::Secrecy::Secret,
        Some(request_kind(&request.mechanism)?),
        &key_id,
    );
    Ok(reply::Exists { exists })
}

fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
    let key_id = request.key;

    let priv_key_der = keystore
        .load_key(
            key::Secrecy::Secret,
            Some(request_kind(&request.mechanism)?),
            &key_id,
        )
        .expect("Failed to load a ML-DSA private key with the given ID")
        .material;

    let priv_key_pkcs8 = pkcs8::PrivateKeyInfo::from_der(&priv_key_der[..])
        .expect("Failed to decode ML-DSA PKCS#8 from DER");

    // TODO: check if this is returning just the signature, or the signed message
    match request.mechanism {
        #[cfg(feature = "mldsa44")]
        Mechanism::Mldsa44 => {
            let priv_key = mldsa44::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load ML-DSA key from PKCS#8");
            let signed_message = mldsa44::detached_sign(&request.message, &priv_key);
            return Ok(reply::Sign {
                signature: Signature::from_slice(signed_message.as_bytes())
                    .expect("Failed to build signature from signed message bytes"),
            });
        }
        #[cfg(feature = "mldsa65")]
        Mechanism::Mldsa65 => {
            let priv_key = mldsa65::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load ML-DSA key from PKCS#8");
            let signed_message = mldsa65::detached_sign(&request.message, &priv_key);
            return Ok(reply::Sign {
                signature: Signature::from_slice(signed_message.as_bytes())
                    .expect("Failed to build signature from signed message bytes"),
            });
        }
        #[cfg(feature = "mldsa87")]
        Mechanism::Mldsa87 => {
            let priv_key = mldsa87::SecretKey::from_bytes(priv_key_pkcs8.private_key)
                .expect("Failed to load ML-DSA key from PKCS#8");
            let signed_message = mldsa87::detached_sign(&request.message, &priv_key);
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
            Some(request_kind(&request.mechanism)?),
            &key_id,
        )
        .unwrap_or_else(|_| panic!("Failed to load a ML-DSA public key with the given ID"))
        .material;

    let pub_key_pkcs8 = pkcs8::SubjectPublicKeyInfoRef::from_der(&pub_key_der[..])
        .expect("Failed to decode ML-DSA PKCS#8 from DER");

    let pub_key_bytes = match pub_key_pkcs8.subject_public_key.as_bytes() {
        Some(b) => b,
        None => return Err(Error::InvalidSerializationFormat),
    };

    match request.mechanism {
        #[cfg(feature = "mldsa44")]
        Mechanism::Mldsa44 => {
            let pub_key = mldsa44::PublicKey::from_bytes(pub_key_bytes)
                .expect("Failed to load ML-DSA public key");
            let sig = match mldsa44::DetachedSignature::from_bytes(request.signature.as_slice()) {
                Ok(sig) => sig,
                Err(_) => return Err(Error::WrongSignatureLength),
            };
            let verification_ok =
                mldsa44::verify_detached_signature(&sig, &request.message, &pub_key).is_ok();
            Ok(reply::Verify {
                valid: verification_ok,
            })
        }
        #[cfg(feature = "mldsa65")]
        Mechanism::Mldsa65 => {
            let pub_key = mldsa65::PublicKey::from_bytes(pub_key_bytes)
                .expect("Failed to load ML-DSA public key");
            let sig = match mldsa65::DetachedSignature::from_bytes(request.signature.as_slice()) {
                Ok(sig) => sig,
                Err(_) => return Err(Error::WrongSignatureLength),
            };
            let verification_ok =
                mldsa65::verify_detached_signature(&sig, &request.message, &pub_key).is_ok();
            Ok(reply::Verify {
                valid: verification_ok,
            })
        }
        #[cfg(feature = "mldsa87")]
        Mechanism::Mldsa87 => {
            let pub_key = mldsa87::PublicKey::from_bytes(pub_key_bytes)
                .expect("Failed to load ML-DSA public key");
            let sig = match mldsa87::DetachedSignature::from_bytes(request.signature.as_slice()) {
                Ok(sig) => sig,
                Err(_) => return Err(Error::WrongSignatureLength),
            };
            let verification_ok =
                mldsa87::verify_detached_signature(&sig, &request.message, &pub_key).is_ok();
            Ok(reply::Verify {
                valid: verification_ok,
            })
        }
        _ => Err(Error::RequestNotAvailable),
    }
}
pub struct SoftwareMldsa;

impl Backend for SoftwareMldsa {
    type Context = ();
    fn request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
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
