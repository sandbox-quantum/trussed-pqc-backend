// Copyright (C) SandboxAQ
// SPDX-License-Identifier: Apache-2.0 or MIT

#![cfg_attr(not(feature = "std"), no_std)]

mod mldsa;
pub use mldsa::SoftwareMldsa;

// For use in Trussed, max sizes that depend
// on the selected features (algorithms).
pub mod sizes;

#[cfg(feature = "virt")]
pub mod virt;
