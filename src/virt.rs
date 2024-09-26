// Copyright (C) Nitrokey GmbH and SandboxAQ
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Wrapper around [`trussed::virt`][] that provides clients with both the core backend and the [`SoftwareDilithium`](crate::SoftwareDilithium) backend.

use crate::SoftwareDilithium;

pub struct Dispatcher;
pub enum BackendIds {
    SoftwareDilithium,
}
impl Dispatch for Dispatcher {
    type BackendId = BackendIds;
    type Context = ();
    fn request<P: Platform>(
        &mut self,
        _backend: &Self::BackendId,
        ctx: &mut trussed::types::Context<Self::Context>,
        request: &trussed::api::Request,
        resources: &mut trussed::service::ServiceResources<P>,
    ) -> Result<trussed::Reply, trussed::Error> {
        SoftwareDilithium.request(&mut ctx.core, &mut ctx.backends, request, resources)
    }
}

use std::path::PathBuf;
use trussed::{
    backend::{Backend, BackendId, Dispatch},
    virt::{self, Filesystem, Ram, StoreProvider},
    Platform,
};

pub type Client<S, D = Dispatcher> = virt::Client<S, D>;

pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    F: FnOnce(Client<S>) -> R,
    S: StoreProvider,
{
    virt::with_platform(store, |platform| {
        platform.run_client_with_backends(
            client_id,
            Dispatcher,
            &[
                BackendId::Custom(BackendIds::SoftwareDilithium),
                BackendId::Core,
            ],
            f,
        )
    })
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Filesystem>) -> R,
    P: Into<PathBuf>,
{
    with_client(Filesystem::new(internal), client_id, f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Ram>) -> R,
{
    with_client(Ram::default(), client_id, f)
}
