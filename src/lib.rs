// Copyright (C) SandboxAQ
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg_attr(not(feature = "std"), no_std)]

use trussed::types::Mechanism;

mod mldsa;
pub use mldsa::SoftwareMldsa;

// For use in Trussed, max sizes that depend
// on the selected features (algorithms).
pub mod sizes;

#[cfg(feature = "virt")]
pub mod virt;

pub const MECHANISMS: &[Mechanism] = &[
    #[cfg(feature = "mldsa44")]
    Mechanism::Mldsa44,
    #[cfg(feature = "mldsa65")]
    Mechanism::Mldsa65,
    #[cfg(feature = "mldsa87")]
    Mechanism::Mldsa87,
];
