use pqcrypto_mldsa::ffi::*;

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

pub const MAX_SIGNATURE_LENGTH: usize = max(
    if cfg!(feature = "mldsa-44") {
        PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES
    } else {
        0
    },
    max(
        if cfg!(feature = "mldsa-65") {
            PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES
        } else {
            0
        },
        if cfg!(feature = "mldsa-87") {
            PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES
        } else {
            0
        },
    ),
);
pub const MAX_PUBLIC_KEY_LENGTH: usize = max(
    if cfg!(feature = "mldsa-44") {
        PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES
    } else {
        0
    },
    max(
        if cfg!(feature = "mldsa-65") {
            PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES
        } else {
            0
        },
        if cfg!(feature = "mldsa-87") {
            PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES
        } else {
            0
        },
    ),
);
pub const MAX_PRIVATE_KEY_LENGTH: usize = max(
    if cfg!(feature = "mldsa-44") {
        PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES
    } else {
        0
    },
    max(
        if cfg!(feature = "mldsa-65") {
            PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES
        } else {
            0
        },
        if cfg!(feature = "mldsa-87") {
            PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES
        } else {
            0
        },
    ),
);
