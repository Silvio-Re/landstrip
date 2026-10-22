// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Temporary filesystem grants for a leased sandbox account.

use super::{LocalSid, is_locked_error, is_missing_error, path_access_failed, set_path_access};
use crate::error::{Error as LandstripError, Mechanism};
use crate::policy::{AccessPolicy, ReadAccess};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Security::Authorization::{
    ACCESS_MODE, DENY_ACCESS, GRANT_ACCESS, REVOKE_ACCESS,
};
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GrantPlan {
    entries: Vec<GrantEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantEntry {
    access_mode: ACCESS_MODE,
    path: PathBuf,
    access: u32,
    inherit: bool,
    propagate: bool,
}

impl GrantPlan {
    pub(super) fn new(policy: &AccessPolicy, request_path: &Path) -> Result<Self> {
        let read_roots = match &policy.read_access {
            ReadAccess::AllowRoots(read_roots) => read_roots,
            ReadAccess::Unrestricted => {
                return Err(LandstripError::PolicyUnrestrictedRead.into());
            }
        };
        let mut plan = Self {
            entries: Vec::new(),
        };
        for path in read_roots {
            plan.add_grant(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, true);
        }
        for path in &policy.write_roots {
            plan.add_grant(
                path,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
                true,
            );
        }
        // Placed after grant entries so the resulting DACL has DENY before
        // GRANT in access-evaluation order.
        for path in &policy.write_denied_roots {
            plan.add_subtree_deny(path, FILE_GENERIC_WRITE | FILE_DELETE_CHILD | DELETE);
        }
        for path in &policy.read_denied_roots {
            plan.add_subtree_deny(path, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | DELETE);
        }
        plan.add_grant(request_path, FILE_GENERIC_READ, false);
        Ok(plan)
    }

    fn add_grant(&mut self, path: &Path, access: u32, inherit_and_propagate: bool) {
        let ancestor_access = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        for ancestor in path.ancestors().skip(1) {
            self.entries.push(GrantEntry {
                access_mode: GRANT_ACCESS,
                path: ancestor.to_path_buf(),
                access: ancestor_access,
                inherit: false,
                propagate: false,
            });
        }
        self.entries.push(GrantEntry {
            access_mode: GRANT_ACCESS,
            path: path.to_path_buf(),
            access,
            inherit: inherit_and_propagate,
            propagate: inherit_and_propagate,
        });
    }

    fn add_subtree_deny(&mut self, path: &Path, access: u32) {
        self.entries.push(GrantEntry {
            access_mode: DENY_ACCESS,
            path: path.to_path_buf(),
            access,
            inherit: true,
            propagate: true,
        });
    }

    pub(super) fn apply(&self, sid: &str) -> Result<Self> {
        let sid = LocalSid::try_from(sid)
            .map_err(|source| LandstripError::sandbox_setup(Mechanism::Windowsuser, source))?;
        let mut applied = Self {
            entries: Vec::with_capacity(self.entries.len()),
        };
        for entry in &self.entries {
            match set_restricted_path_access(
                &entry.path,
                sid.as_ptr(),
                entry.access,
                entry.access_mode,
                entry.inherit,
                entry.propagate,
                false,
            ) {
                Ok(true) => applied.entries.push(entry.clone()),
                Ok(false) => {}
                Err(error) => {
                    for applied_entry in applied.entries.iter().rev() {
                        let _ = set_restricted_path_access(
                            &applied_entry.path,
                            sid.as_ptr(),
                            0,
                            REVOKE_ACCESS,
                            false,
                            applied_entry.propagate,
                            true,
                        );
                    }
                    return Err(error);
                }
            }
        }
        Ok(applied)
    }

    pub(super) fn revoke(&self, sid: &str) -> Result<()> {
        let sid = LocalSid::try_from(sid)
            .map_err(|source| LandstripError::sandbox_setup(Mechanism::Windowsuser, source))?;
        let mut first_error = None;
        for entry in self.entries.iter().rev() {
            let error = set_restricted_path_access(
                &entry.path,
                sid.as_ptr(),
                0,
                REVOKE_ACCESS,
                false,
                entry.propagate,
                true,
            )
            .err();
            if first_error.is_none() {
                first_error = error;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn set_restricted_path_access(
    path: &Path,
    sid: PSID,
    access: u32,
    mode: ACCESS_MODE,
    inherit: bool,
    propagate: bool,
    ignore_missing: bool,
) -> Result<bool> {
    match set_path_access(path, sid, access, mode, inherit, propagate) {
        Ok(()) => Ok(true),
        Err((api, error))
            if api != "SetEntriesInAclW" && ignore_missing && is_missing_error(&error) =>
        {
            Ok(false)
        }
        // A failed non-propagating grant did not alter descendants and leaves
        // the target inaccessible. Propagating failures may be partial, so they
        // remain hard errors and the full journal is retained for recovery.
        Err((api, error))
            if (api == "GetNamedSecurityInfoW" || !propagate)
                && mode == GRANT_ACCESS
                && is_locked_error(&error) =>
        {
            Ok(false)
        }
        Err((api, error)) => {
            Err(path_access_failed(Mechanism::Windowsuser, path, mode, api, &error).into())
        }
    }
}
