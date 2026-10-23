// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Windows restricted-user sandbox implementation.

mod access;
mod account;
mod broker;
mod lease;
mod manage;
mod state;
mod wfp;
mod worker;

pub(super) use super::{
    LocalSid, NamedMutex, OwnedLocal, OwnedSecurityDescriptor, PathAccessEntry, SandboxJob,
    ToWideNul, current_process_token, decode_hex, encode_hex, is_locked_error, is_missing_error,
    join_command_line, own_handle, path_access_failed, quote_command_arg, sid_string, token_user,
    wait_process_exit, win32_error,
};

use crate::error::{Error, Mechanism};
use crate::policy::AccessPolicy;
use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;

pub(super) use manage::active_implementation;
pub(crate) use manage::{manage, status};
pub(crate) use worker::run as run_worker;

pub(super) fn is_installed() -> Result<bool> {
    Ok(state::Installation::load_optional()?.is_some())
}
pub(super) fn execute(
    policy: &AccessPolicy,
    cwd: &Path,
    tool: &OsStr,
    args: &[OsString],
) -> Result<i32> {
    let installation = state::Installation::load_ready()?;
    let network_mode = if policy.network_access.is_unrestricted() {
        state::NetworkMode::Unrestricted
    } else {
        installation.validate_restricted_network(policy)?;
        state::NetworkMode::Restricted
    };
    let lease = lease::Lease::acquire(&installation, network_mode)?;
    let state_dir = state::state_dir()
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    let request_id = account::random_identifier(16)
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    let request_path = state_dir.join("runs").join(format!("{request_id}.json"));
    let grants = access::GrantPlan::new(policy, &request_path)?;
    worker::write_request(&request_path, &lease.account().sid, tool, args, cwd)
        .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))?;
    if let Err(error) = lease.write_journal(&grants) {
        let _ = fs::remove_file(&request_path);
        return Err(Error::sandbox_setup(Mechanism::Windowsuser, error).into());
    }

    let applied_grants;
    let launch_result = match grants.apply(&lease.account().sid) {
        Ok(applied) => {
            // Replace the crash-recovery plan with only entries that reached the
            // DACL update. Pre-update locked grants need no later revocation.
            if let Err(error) = lease.write_journal(&applied) {
                let revoke_result = applied.revoke(&lease.account().sid);
                if revoke_result.is_ok() {
                    let _ = lease.clear_journal();
                }
                let _ = fs::remove_file(&request_path);
                return Err(Error::sandbox_setup(Mechanism::Windowsuser, error).into());
            }
            applied_grants = applied;
            broker::launch(lease.account(), &installation.runner_path, &request_path)
        }
        Err(error) => {
            // A propagating update can fail after partial mutation. Keep and
            // revoke the full pre-apply journal rather than narrowing it.
            applied_grants = grants.clone();
            Err(error)
        }
    };
    let revoke_result = applied_grants.revoke(&lease.account().sid);
    let clear_result = if revoke_result.is_ok() {
        lease
            .clear_journal()
            .map_err(|source| Error::sandbox_setup(Mechanism::Windowsuser, source))
    } else {
        Ok(())
    };
    let _ = fs::remove_file(&request_path);
    let exit_code = launch_result?;
    revoke_result?;
    clear_result?;
    Ok(exit_code.cast_signed())
}

pub(super) fn validate(policy: &AccessPolicy) -> Result<()> {
    let installation = state::Installation::load_ready()?;
    if !policy.network_access.is_unrestricted() {
        installation.validate_restricted_network(policy)?;
    }
    Ok(())
}
