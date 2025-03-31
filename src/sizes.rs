use pqcrypto_mldsa::ffi::*;

const fn max(values: &[usize]) -> usize {
    let mut max = 0;
    let mut i = 0;
    while i < values.len() {
        if values[i] > max {
            max = values[i];
        }
        i += 1;
    }
    max
}

pub const MAX_SIGNATURE_LENGTH: usize = max(&[
    #[cfg(feature = "mldsa44")]
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
    #[cfg(feature = "mldsa65")]
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES,
    #[cfg(feature = "mldsa87")]
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES,
]);

pub const MAX_PUBLIC_KEY_LENGTH: usize = max(&[
    #[cfg(feature = "mldsa44")]
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
    #[cfg(feature = "mldsa65")]
    PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
    #[cfg(feature = "mldsa87")]
    PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES,
]);

pub const MAX_PRIVATE_KEY_LENGTH: usize = max(&[
    #[cfg(feature = "mldsa44")]
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
    #[cfg(feature = "mldsa65")]
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
    #[cfg(feature = "mldsa87")]
    PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
]);
