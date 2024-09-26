use pqcrypto_dilithium::ffi::*;

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

pub const MAX_SIGNATURE_LENGTH: usize = max(
    if cfg!(feature = "dilithium2") {
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES
    } else {
        0
    },
    max(
        if cfg!(feature = "dilithium3") {
            PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES
        } else {
            0
        },
        if cfg!(feature = "dilithium5") {
            PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES
        } else {
            0
        },
    ),
);
pub const MAX_PUBLIC_KEY_LENGTH: usize = max(
    if cfg!(feature = "dilithium2") {
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES
    } else {
        0
    },
    max(
        if cfg!(feature = "dilithium3") {
            PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES
        } else {
            0
        },
        if cfg!(feature = "dilithium5") {
            PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES
        } else {
            0
        },
    ),
);
pub const MAX_PRIVATE_KEY_LENGTH: usize = max(
    if cfg!(feature = "dilithium2") {
        PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES
    } else {
        0
    },
    max(
        if cfg!(feature = "dilithium3") {
            PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES
        } else {
            0
        },
        if cfg!(feature = "dilithium5") {
            PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES
        } else {
            0
        },
    ),
);
